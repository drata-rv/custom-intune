"""Extractor pipeline stage -- fetch, normalize, and validate Intune device data.

Exported function:
    run(intune: IntuneClient) -> list[dict[str, Any]]

Fetches all managed devices from Intune and the per-device compliance states
for each customer-configured policy or Update Ring, joins them by Intune device
GUID, validates each merged record via Pydantic, and returns the validated
payloads as dicts ready for the publisher stage.

Two distinct Intune resource types are queried:
    - Compliance policies (/deviceManagement/deviceCompliancePolicies)
      for screenLockEnabled, passwordManagerEnabled, encryptionEnabled,
      antivirusEnabled.
    - Windows Update Rings (/deviceManagement/windowsUpdateForBusinessConfigurations)
      for autoUpdateEnabled. Update Rings are NOT compliance policies -- looking
      up an Update Ring display name against the compliance policy endpoint
      always returns nothing.

Also writes ``drata_payloads.json`` as a debug artifact. The publisher does not
read this file -- payloads are passed in memory between stages.

Raises ``ExtractorError`` on unrecoverable failures. Per-device validation errors
and individual policy/ring fetch failures are non-fatal: affected devices or
check types are logged and skipped.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Optional

import structlog
from pydantic import ValidationError

from clients.intune_client import IntuneClient
from core.normalizer import (
    build_drata_payload,
    map_compliance_state,
    map_update_ring_status,
)
from models.source_models import ComplianceState, IntuneDevice, PolicyDeviceStatus

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

PAYLOADS_FILE = Path("drata_payloads.json")

# Resolved via /deviceManagement/deviceCompliancePolicies
_COMPLIANCE_POLICY_FIELDS: dict[str, str] = {
    "screenLockEnabled":      "POLICY_NAME_SCREEN_LOCK",
    "passwordManagerEnabled": "POLICY_NAME_PASSWORD_MANAGER",
    "encryptionEnabled":      "POLICY_NAME_ENCRYPTION",
    "antivirusEnabled":       "POLICY_NAME_ANTIVIRUS",
}

# Resolved via /deviceManagement/windowsUpdateForBusinessConfigurations.
# Update Rings are a separate Intune resource type -- they will never appear
# in a compliance policy listing and vice versa.
_UPDATE_RING_FIELDS: dict[str, str] = {
    "autoUpdateEnabled": "POLICY_NAME_AUTO_UPDATES",
}


class ExtractorError(RuntimeError):
    """Fatal extraction failure -- pipeline cannot continue."""


def _read_configured_checks(field_map: dict[str, str]) -> dict[str, str]:
    """Read env vars from ``field_map`` and return {check_type: display_name}.

    Logs a WARNING for each unconfigured check type. Returns an empty dict if
    none are set -- non-fatal; those fields will simply be absent from all payloads.
    """
    configured: dict[str, str] = {}
    for check_type, env_var in field_map.items():
        display_name = os.environ.get(env_var, "").strip()
        if display_name:
            configured[check_type] = display_name
        else:
            logger.warning(
                "check_not_configured",
                check_type=check_type,
                env_var=env_var,
                hint="Field will be omitted from all payloads",
            )
    return configured


def _build_compliance_index(
    results: list[tuple[str, list[PolicyDeviceStatus] | BaseException]],
    status_mapper: Callable[[str], Optional[bool]],
) -> dict[str, ComplianceState]:
    """Build a device-id-keyed compliance state index from a set of fetch results.

    ``status_mapper`` translates raw Intune status strings to True/False/None.
    Pass ``map_compliance_state`` for compliance policy results and
    ``map_update_ring_status`` for Update Ring results -- the two APIs use
    different status vocabularies and must not share a mapper.

    For each result:
        - On exception: log ERROR, omit that check type for all devices this run.
        - On empty list: log WARNING -- policy/ring may have no device assignments.

    Only deterministic states (True or False) are stored. A missing key means
    "no reliable data for this check."

    Returns:
        {managedDeviceId: {check_type: bool}}
    """
    index: dict[str, ComplianceState] = defaultdict(dict)

    for check_type, result in results:
        if isinstance(result, BaseException):
            logger.error(
                "check_fetch_failed",
                check_type=check_type,
                error=str(result),
                action="omitting field from all payloads this run",
            )
            continue

        statuses: list[PolicyDeviceStatus] = result

        if not statuses:
            logger.warning(
                "check_returned_no_statuses",
                check_type=check_type,
                hint="Check policy/ring assignments in Intune -- no devices may be targeted",
            )
            continue

        matched = 0
        for status_record in statuses:
            value = status_mapper(status_record.status)
            if value is not None:
                index[status_record.device_id][check_type] = value
                matched += 1

        logger.info(
            "check_index_built",
            check_type=check_type,
            total_statuses=len(statuses),
            deterministic_states=matched,
            indeterminate_skipped=len(statuses) - matched,
        )

    return dict(index)


def _merge_indices(
    base: dict[str, ComplianceState],
    overlay: dict[str, ComplianceState],
) -> dict[str, ComplianceState]:
    """Merge ``overlay`` into ``base`` in-place and return ``base``.

    Both dicts map managedDeviceId -> {check_type: bool}. Keys from ``overlay``
    are added to the corresponding device entry in ``base``; they do not overwrite
    existing check types.
    """
    for device_id, checks in overlay.items():
        if device_id in base:
            base[device_id].update(checks)
        else:
            base[device_id] = checks
    return base


async def run(intune: IntuneClient) -> list[dict[str, Any]]:
    """Fetch all devices and compliance/ring state from Intune; return validated Drata payloads.

    Args:
        intune: An initialized ``IntuneClient`` within an active async context manager.

    Returns:
        List of serialized Drata device payloads ready to push.

    Raises:
        ExtractorError: Intune returned zero devices, or the device fetch failed entirely.
    """
    logger.info("extractor_start")

    configured_compliance = _read_configured_checks(_COMPLIANCE_POLICY_FIELDS)
    configured_rings = _read_configured_checks(_UPDATE_RING_FIELDS)

    if not configured_compliance and not configured_rings:
        logger.warning(
            "no_checks_configured",
            hint="Set at least one POLICY_NAME_* env var to enable compliance checks. "
                 "Device identity will still be pushed to Drata.",
        )

    # Resolve display names to GUIDs concurrently -- both are single-page fast
    # requests and neither depends on the other's result.
    resolved_compliance_ids, resolved_ring_ids = await asyncio.gather(
        intune.resolve_policy_ids(configured_compliance),
        intune.resolve_update_ring_ids(configured_rings),
    )

    missing_policies = [k for k in configured_compliance if k not in resolved_compliance_ids]
    missing_rings = [k for k in configured_rings if k not in resolved_ring_ids]
    if missing_policies:
        logger.warning(
            "policies_not_found_in_intune",
            missing=missing_policies,
            hint="Check that POLICY_NAME_* values match exactly (case-insensitive) in Intune",
        )
    if missing_rings:
        logger.warning(
            "update_rings_not_found",
            missing=missing_rings,
            hint="Check that POLICY_NAME_AUTO_UPDATES matches an Update Ring display name, "
                 "not a compliance policy",
        )

    compliance_fetch_order = list(resolved_compliance_ids.keys())
    ring_fetch_order = list(resolved_ring_ids.keys())

    # Device inventory, compliance policy statuses, and Update Ring statuses all
    # run concurrently. return_exceptions=True lets us handle per-task failures
    # without aborting the entire gather -- a failed policy/ring fetch is
    # non-fatal (fields omitted), but a failed device fetch is fatal.
    all_results: list[Any] = await asyncio.gather(
        intune.fetch_all_devices(),
        *[
            intune.fetch_policy_device_statuses(resolved_compliance_ids[ct], ct)
            for ct in compliance_fetch_order
        ],
        *[
            intune.fetch_update_ring_device_statuses(resolved_ring_ids[ct], ct)
            for ct in ring_fetch_order
        ],
        return_exceptions=True,
    )

    device_result = all_results[0]
    n_compliance = len(compliance_fetch_order)
    compliance_results_raw = all_results[1 : 1 + n_compliance]
    ring_results_raw = all_results[1 + n_compliance :]

    if isinstance(device_result, BaseException):
        raise ExtractorError(f"Intune device fetch failed: {device_result}")

    intune_devices: list[IntuneDevice] = device_result

    if not intune_devices:
        raise ExtractorError(
            "Intune returned zero devices. "
            "Check Azure AD credentials and admin consent grants."
        )

    # Build separate indices with the correct status mapper for each resource type,
    # then merge so the join loop sees a unified {device_id: {check_type: bool}}.
    compliance_results = list(zip(compliance_fetch_order, compliance_results_raw))
    ring_results = list(zip(ring_fetch_order, ring_results_raw))

    compliance_index = _build_compliance_index(compliance_results, map_compliance_state)
    ring_index = _build_compliance_index(ring_results, map_update_ring_status)
    combined_index = _merge_indices(compliance_index, ring_index)

    valid_payloads: list[dict[str, Any]] = []
    validation_errors = 0
    platform_skips = 0
    compliance_hit_count = 0

    for device in intune_devices:
        # Direct GUID join -- Intune is the sole source of truth, so its
        # device IDs are the authoritative join key. No serial/hostname fallback.
        compliance: ComplianceState = combined_index.get(device.id, {})
        if compliance:
            compliance_hit_count += 1

        try:
            payload = build_drata_payload(device, compliance)
            valid_payloads.append(payload.to_drata_dict())
        except ValueError:
            # map_platform() already logged WARNING with device id and OS string
            platform_skips += 1
        except ValidationError as exc:
            validation_errors += 1
            logger.error(
                "payload_validation_failed",
                external_id=device.id,
                device_name=device.device_name,
                operating_system=device.operating_system,
                error=str(exc),
            )

    logger.info(
        "extractor_summary",
        intune_total=len(intune_devices),
        configured_compliance_checks=list(configured_compliance.keys()),
        configured_ring_checks=list(configured_rings.keys()),
        resolved_compliance_policies=list(resolved_compliance_ids.keys()),
        resolved_update_rings=list(resolved_ring_ids.keys()),
        missing_policies=missing_policies,
        missing_rings=missing_rings,
        devices_with_compliance_data=compliance_hit_count,
        platform_skips=platform_skips,
        validation_errors=validation_errors,
        valid_payloads=len(valid_payloads),
    )

    if validation_errors > 0:
        logger.warning(
            "validation_errors_detected",
            count=validation_errors,
            hint="Devices with missing personnelId (no UPN) or unsupported OS are skipped",
        )

    _write_payloads_file(valid_payloads)

    logger.info("extractor_complete", payload_count=len(valid_payloads))
    return valid_payloads


def _write_payloads_file(payloads: list[dict[str, Any]]) -> None:
    """Atomically write payloads to drata_payloads.json for debugging.

    Non-fatal if the write fails -- the publisher uses the in-memory list,
    not this file.
    """
    tmp_path = PAYLOADS_FILE.with_suffix(".tmp")
    try:
        tmp_path.write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        os.replace(tmp_path, PAYLOADS_FILE)
        logger.debug("payloads_file_written", path=str(PAYLOADS_FILE), count=len(payloads))
    except OSError as exc:
        logger.warning("payloads_file_write_failed", error=str(exc))
