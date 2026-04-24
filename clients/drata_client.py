"""Drata Custom MDM Connection API client -- device upsert.

This client is intentionally thin: it POSTs a single device payload and
returns a named tuple of (status_code, body, headers). It does NOT raise on
4xx/5xx -- callers (pipeline/publisher) handle status codes, apply retry and
dead-letter logic, and read headers (e.g., Retry-After on 429) directly.

The Drata API upserts: if a device matching ``externalId``, ``serialNumber``,
or ``macAddress`` already exists, it updates the record. Otherwise it creates
a new one.
"""

from __future__ import annotations

import os
from typing import Any, NamedTuple

import httpx
import structlog

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


class DrataResponse(NamedTuple):
    """Return value of ``DrataClient.upsert_device``.

    Using a NamedTuple rather than a plain tuple makes caller code self-documenting
    (``resp.status_code`` vs ``resp[0]``) and makes the added ``headers`` field
    backwards-compatible with any code that already unpacks ``(status, body)``.
    """

    status_code: int
    body: dict[str, Any]
    headers: dict[str, str]  # lowercased header names, e.g. "retry-after"


class DrataClient:
    """Pushes device compliance payloads to Drata's Custom MDM endpoint.

    Requires env vars:
        - ``DRATA_API_KEY``
        - ``DRATA_CONNECTION_ID``
    """

    def __init__(self) -> None:
        self._api_key: str = self._require_env("DRATA_API_KEY")
        connection_id = self._require_env("DRATA_CONNECTION_ID")

        self._url: str = (
            f"https://public-api.drata.com/public/v2"
            f"/custom-connections/{connection_id}/devices"
        )

    async def upsert_device(
        self,
        client: httpx.AsyncClient,
        payload: dict[str, Any],
    ) -> DrataResponse:
        """POST a single device payload to Drata.

        Returns ``DrataResponse(status_code, body, headers)``. Does NOT raise
        on HTTP errors -- the caller interprets status codes and reads headers
        (particularly ``retry-after`` on 429 responses).

        The ``client`` is passed in (not created here) so that the publisher can
        reuse a single ``httpx.AsyncClient`` across all concurrent requests,
        benefiting from connection pooling.
        """
        request_headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            response = await client.post(
                self._url,
                json=payload,
                headers=request_headers,
            )
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text}

            # httpx headers are case-insensitive; convert to a plain dict with
            # lowercased keys so callers can do headers.get("retry-after") reliably.
            resp_headers = dict(response.headers.items())

            return DrataResponse(
                status_code=response.status_code,
                body=body,
                headers=resp_headers,
            )

        except httpx.TimeoutException as exc:
            logger.error(
                "drata_request_timeout",
                external_id=payload.get("externalId"),
                error=str(exc),
            )
            return DrataResponse(503, {"error": f"Request timed out: {exc}"}, {})

        except httpx.RequestError as exc:
            logger.error(
                "drata_request_error",
                external_id=payload.get("externalId"),
                error=str(exc),
            )
            return DrataResponse(503, {"error": f"Connection error: {exc}"}, {})

    @staticmethod
    def _require_env(name: str) -> str:
        value = os.environ.get(name)
        if not value:
            raise EnvironmentError(
                f"Required environment variable '{name}' is not set or empty. "
                f"See .env.example for the full list."
            )
        return value
