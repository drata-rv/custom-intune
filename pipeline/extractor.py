"""Extractor pipeline stage -- fetch, normalize, and validate Intune device data.

Exported function:
    run(intune: IntuneClient) -> list[dict[str, Any]]

Fetches all managed devices from Intune and the per-device compliance states
for each customer-configured policy, joins them by Intune device GUID, validates
each merged record via Pydantic, and returns the validated payloads as dicts
ready for the publisher stage.

Also writes ``drata_payloads.json`` as a debug artifact so that payloads can be
inspected without re-running the full extraction. The publisher does not read
this file -- payloads are passed in memory between stages.

Raises ``ExtractorError`` on unrecoverable failures (zero devices returned,
file write failure). Per-device validation errors and individual policy fetch
failures are non-fatal: affected devices or check types are logged and skipped.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import structlog
from pydantic import ValidationError

from clients.intune_client import IntuneClient
from core.normalizer import build_drata_payload, map_compliance_state
from models.source_models import ComplianceState, IntuneDevice, PolicyDeviceStatus

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

PAYLOADS_FILE = Path("drata_payloads.json")

# Maps each Drata compliance field name to the env var holding the customer's
# Intune policy display name. To add a new compliance check, add one entry here
# and the corresponding field in DrataDevicePayload.
POLICY_CHECK_FIELDS: dict[str, str] = {
    "screenLockEnabled":      "POLICY_NAME_SCREEN_LOCK",
    "autoUpdateEnabled":      "POLICY_NAME_AUTO_UPDATES",
    "passwordManagerEnabled": "POLICY_NAME_PASSWORD_MANAGER",
    "encryptionEnabled":      "POLICY_NAME_ENCRYPTION",
    "antivirusEnabled":       "POLICY_NAME_ANTIVIRUS",
}


class ExtractorError(RuntimeError):
    """Fatal extraction failure -- pipeline cannot continue."""


def _read_configured_policies() -> dict[str, str]:
    """Read POLICY_NAME_* env vars and return {check_type: display_name}.

    Logs a WARNING for each unconfigured check type. Returns an empty dict if
    none are configured -- non-fatal; device identity will still be pushed to
    Drata, just without any compliance fields.
    """
    configured: dict[str, str] = {}
    for check_type, env_var in POLICY_CHECK_FIELDS.items():
        display_name = os.environ.get(env_var, "").strip()
        if display_name:
            configured[check_type] = display_name
        else:
            logger.warning(
                "policy_not_configured",
                check_type=check_type,
                env_var=env_var,
                hint="Field will be omitted from all payloads",
            )
    return configured


def _build_compliance_index(
    policy_results: list[tuple[str, list[PolicyDeviceStatus] | BaseException]],
) -> dict[str, ComplianceState]:
    """Build a device-id-keyed compliance state index from policy fetch results.

    For each policy result:
        - On exception: log ERROR, omit that check type for all devices this run.
          Better to omit than to emit stale or incorrect data.
        - On empty list: log WARNING -- policy may have no device assignments.

    Only deterministic states (compliant -> True, noncompliant -> False) are
    stored. A missing key unambiguously means "no reliable data for this check."

    Returns:
        {managedDeviceId: {check_type: bool}}
    """
    index: dict[str, ComplianceState] = defaultdict(dict)

    for check_type, result in policy_results:
        if isinstance(result, BaseException):
            logger.error(
                "policy_fetch_failed",
                check_type=check_type,
                error=str(result),
                action="omitting field from all payloads this run",
            )
            continue

        statuses: list[PolicyDeviceStatus] = result

        if not statuses:
            logger.warning(
                "policy_returned_no_statuses",
                check_type=check_type,
                hint="Check policy assignments in Intune -- no devices may be targeted",
            )
            continue

        matched = 0
        for status_record in statuses:
            value = map_compliance_state(status_record.status)
            if value is not None:
                index[status_record.device_id][check_type] = value
                matched += 1

        logger.info(
            "compliance_index_built",
            check_type=check_type,
            total_statuses=len(statuses),
            deterministic_states=matched,
            indeterminate_skipped=len(statuses) - matched,
        )

    return dict(index)


async def run(intune: IntuneClient) -> list[dict[str, Any]]:
    """Fetch all devices and compliance state from Intune; return validated Drata payloads.

    Args:
        intune: An initialized ``IntuneClient`` within an active async context manager.

    Returns:
        List of serialized Drata device payloads ready to push.

    Raises:
        ExtractorError: Intune returned zero devices, or the debug artifact
                        could not be written to disk.
    """
    logger.info("extractor_start")

    configured_policy_names = _read_configured_policies()

    if not configured_policy_names:
        logger.warning(
            "no_policies_configured",
            hint="Set at least one POLICY_NAME_* env var to enable compliance checks. "
                 "Device identity will still be pushed to Drata.",
        )

    # Resolve policy display names to GUIDs before the concurrent gather.
    # Sequential -- a single fast request that must complete before we can
    # schedule per-policy status fetches.
    resolved_policy_ids: dict[str, str] = await intune.resolve_policy_ids(
        configured_policy_names
    )

    missing_policies = [k for k in configured_policy_names if k not in resolved_policy_ids]
    if missing_policies:
        logger.warning(
            "policies_not_found_in_intune",
            missing=missing_policies,
            hint="Check that POLICY_NAME_* values match exactly (case-insensitive) in Intune",
        )

    # Device inventory and all policy status fetches run concurrently.
    # return_exceptions=True lets us handle per-task failures without aborting
    # the entire gather -- a failed policy fetch is non-fatal (fields omitted),
    # but a failed device fetch is fatal (handled below).
    policy_fetch_order: list[str] = list(resolved_policy_ids.keys())

    all_results: list[Any] = await asyncio.gather(
        intune.fetch_all_devices(),
        *[
            intune.fetch_policy_device_statuses(resolved_policy_ids[ct], ct)
            for ct in policy_fetch_order
        ],
        return_exceptions=True,
    )

    device_result = all_results[0]
    policy_results_raw = all_results[1:]

    if isinstance(device_result, BaseException):
        raise ExtractorError(f"Intune device fetch failed: {device_result}")

    intune_devices: list[IntuneDevice] = device_result

    if not intune_devices:
        raise ExtractorError(
            "Intune returned zero devices. "
            "Check Azure AD credentials and admin consent grants."
        )

    policy_results: list[tuple[str, list[PolicyDeviceStatus] | BaseException]] = [
        (ct, result) for ct, result in zip(policy_fetch_order, policy_results_raw)
    ]
    compliance_index = _build_compliance_index(policy_results)

    valid_payloads: list[dict[str, Any]] = []
    validation_errors = 0
    platform_skips = 0
    compliance_hit_count = 0

    for device in intune_devices:
        # Direct GUID join -- Intune is the sole source of truth, so its
        # device IDs are the authoritative join key. No serial/hostname fallback.
        compliance: ComplianceState = compliance_index.get(device.id, {})
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
        configured_checks=list(configured_policy_names.keys()),
        resolved_policies=list(resolved_policy_ids.keys()),
        missing_policies=missing_policies,
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
