"""Publisher pipeline stage -- delta-detect and push changed devices to Drata.

Exported function:
    run(payloads, dry_run=False) -> None

Reads the provided payloads, performs SHA-256 delta detection against
``drata_state.json``, and pushes only changed devices to the Drata Custom MDM
Connection API.

Concurrency is bounded by ``asyncio.Semaphore(8)`` and rate-limited by a
token-bucket capped at 7 req/sec (420 req/min), a 15% safety margin below
Drata's 500 req/min hard limit.

Raises ``PublisherHaltError`` if Drata responds with 401, 403, or 412 -- these
indicate credential or precondition failures that cannot be retried. State is
persisted before raising so that successfully pushed devices are not re-pushed
on the next run.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import structlog

from clients.drata_client import DrataClient, DrataResponse
from core.rate_limiter import TokenBucket
from core.state import StateManager

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_SEMAPHORE_LIMIT = 8         # max in-flight Drata requests
_RATE_LIMIT_PER_SEC = 7.0    # 7 req/sec = 420 req/min (500 limit - 15% margin)

_RETRYABLE_STATUSES = {429, 500, 503}
_HALT_STATUSES = {401, 403, 412}


class PublisherHaltError(RuntimeError):
    """Authentication or precondition failure from Drata -- pipeline cannot continue."""


def _parse_retry_after(headers: dict[str, str], fallback: float) -> float:
    """Extract retry delay from Drata's response headers.

    Drata sends ``retry-after`` in seconds on 429 responses. If the header is
    absent or unparseable, fall back to the caller-provided exponential value.
    Capped at 120 seconds to avoid indefinite stalls.
    """
    raw = headers.get("retry-after")
    if raw:
        try:
            return min(float(raw), 120.0)
        except ValueError:
            pass
    return fallback


def _get_state_path() -> Path:
    override = os.environ.get("STATE_FILE_PATH")
    if override:
        return Path(override)
    return Path("drata_state.json")


class _DeadLetterWriter:
    """Accumulates failed device payloads and writes them to an NDJSON file."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []

    def add(
        self,
        external_id: str,
        status_code: int,
        error: Any,
        payload: dict[str, Any],
    ) -> None:
        self._entries.append({
            "externalId": external_id,
            "status_code": status_code,
            "error": error,
            "payload": payload,
        })

    def write_if_needed(self) -> Path | None:
        """Write accumulated entries to a timestamped NDJSON file.

        Returns the file path if entries were written, otherwise ``None``.
        """
        if not self._entries:
            return None

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = Path(f"dead_letter_{ts}.ndjson")

        with path.open("w", encoding="utf-8") as f:
            for entry in self._entries:
                f.write(json.dumps(entry) + "\n")

        logger.warning("dead_letter_written", path=str(path), count=len(self._entries))
        return path

    @property
    def count(self) -> int:
        return len(self._entries)


async def run(
    payloads: list[dict[str, Any]],
    dry_run: bool = False,
) -> None:
    """Push changed device payloads to Drata.

    Args:
        payloads: Validated Drata device payloads from the extractor stage.
        dry_run:  If True, compute deltas and log what would be pushed without
                  making any Drata API calls.

    Raises:
        EnvironmentError:    Required Drata env vars (DRATA_API_KEY, DRATA_CONNECTION_ID)
                             are missing.
        PublisherHaltError:  Drata responded with 401, 403, or 412. State is
                             persisted before raising.
    """
    logger.info("publisher_start", total_payloads=len(payloads), dry_run=dry_run)

    state = StateManager(_get_state_path())
    state.load()

    to_push: list[dict[str, Any]] = [
        p for p in payloads
        if state.is_changed(p.get("externalId", ""), p)
    ]
    skipped = len(payloads) - len(to_push)

    logger.info(
        "delta_filter_complete",
        total_payloads=len(payloads),
        to_push=len(to_push),
        skipped_unchanged=skipped,
    )

    if dry_run:
        sample_ids = [p.get("externalId", "?") for p in to_push[:10]]
        logger.info(
            "dry_run_summary",
            would_push=len(to_push),
            skipped=skipped,
            sample_external_ids=sample_ids,
        )
        logger.info("publisher_dry_run_complete")
        return

    if not to_push:
        logger.info("nothing_to_push", note="all devices unchanged since last run")
        return

    drata = DrataClient()  # raises EnvironmentError if vars are missing

    semaphore = asyncio.Semaphore(_SEMAPHORE_LIMIT)
    rate_limiter = TokenBucket(rate=_RATE_LIMIT_PER_SEC, per=1.0)
    dead_letter = _DeadLetterWriter()

    success_count = 0
    fail_count = 0
    halt_event = asyncio.Event()

    async def push_one(
        client: httpx.AsyncClient,
        payload: dict[str, Any],
    ) -> None:
        nonlocal success_count, fail_count

        if halt_event.is_set():
            return

        external_id = payload.get("externalId", "unknown")

        async with semaphore:
            await rate_limiter.acquire()

            if halt_event.is_set():
                return

            attempts = 0
            max_attempts = 5
            resp = DrataResponse(0, {}, {})

            while attempts < max_attempts:
                attempts += 1
                resp = await drata.upsert_device(client, payload)

                if resp.status_code in {200, 201}:
                    # 201 = created (new device), 200 = updated (existing device).
                    # Drata's upsert returns both -- treating only 201 as success
                    # caused every update to be retried 5x and dead-lettered.
                    logger.info(
                        "device_pushed",
                        external_id=external_id,
                        action="created" if resp.status_code == 201 else "updated",
                    )
                    state.record_success(external_id, payload)
                    success_count += 1
                    return

                if resp.status_code == 404:
                    # Expected for service accounts / no matching UPN in Drata.
                    logger.warning(
                        "device_personnel_not_found",
                        external_id=external_id,
                        personnel_id=payload.get("personnelId"),
                    )
                    return

                if resp.status_code in _HALT_STATUSES:
                    logger.critical(
                        "drata_auth_or_precondition_failure",
                        external_id=external_id,
                        status_code=resp.status_code,
                        body=resp.body,
                    )
                    halt_event.set()
                    return

                if resp.status_code == 400:
                    # Client validation error -- no point retrying the same payload.
                    logger.error(
                        "drata_validation_error",
                        external_id=external_id,
                        status_code=resp.status_code,
                        body=resp.body,
                    )
                    dead_letter.add(external_id, resp.status_code, resp.body, payload)
                    fail_count += 1
                    return

                if resp.status_code in _RETRYABLE_STATUSES:
                    retry_after = _parse_retry_after(resp.headers, fallback=2 ** attempts)
                    logger.warning(
                        "drata_retryable_error",
                        external_id=external_id,
                        status_code=resp.status_code,
                        attempt=attempts,
                        retry_after_seconds=retry_after,
                    )
                    await asyncio.sleep(retry_after)
                    continue

                # Unexpected status code -- treat as retryable with standard backoff.
                logger.warning(
                    "drata_unexpected_status",
                    external_id=external_id,
                    status_code=resp.status_code,
                    body=resp.body,
                    attempt=attempts,
                )
                await asyncio.sleep(2 ** attempts)

            # Exhausted retries
            logger.error(
                "drata_retries_exhausted",
                external_id=external_id,
                final_status=resp.status_code,
                body=resp.body,
            )
            dead_letter.add(external_id, resp.status_code, resp.body, payload)
            fail_count += 1

    async with httpx.AsyncClient(timeout=30.0) as client:
        tasks = [push_one(client, p) for p in to_push]
        await asyncio.gather(*tasks)

    # Persist state regardless of halt -- capture whatever succeeded.
    state.persist()

    dl_path = dead_letter.write_if_needed()

    logger.info(
        "publisher_summary",
        pushed=len(to_push),
        skipped=skipped,
        succeeded=success_count,
        failed=fail_count,
        dead_lettered=dead_letter.count,
        dead_letter_path=str(dl_path) if dl_path else None,
    )

    if halt_event.is_set():
        raise PublisherHaltError(
            "Drata returned a credential or precondition error (401/403/412). "
            "Check DRATA_API_KEY and DRATA_CONNECTION_ID."
        )

    if dead_letter.count > 0:
        logger.warning(
            "publisher_completed_with_failures",
            hint="Inspect dead_letter_*.ndjson for payloads that Drata rejected",
        )

    logger.info("publisher_complete")
