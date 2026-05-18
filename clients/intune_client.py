"""Microsoft Graph / Intune client -- device inventory and compliance policy states.

Three public async methods:
    - ``fetch_all_devices()``            -- paginated device inventory
    - ``resolve_policy_ids()``           -- maps display names to policy GUIDs
    - ``fetch_policy_device_statuses()`` -- per-policy device compliance states

Authentication uses the OAuth2 client-credentials flow via MSAL's
``ConfidentialClientApplication``. Token caching and silent renewal are
handled by MSAL's built-in token cache.

Must be used as an async context manager so that a single ``httpx.AsyncClient``
is shared across all concurrent method calls:

    async with IntuneClient() as intune:
        devices, statuses = await asyncio.gather(
            intune.fetch_all_devices(),
            intune.fetch_policy_device_statuses(policy_id, "encryptionEnabled"),
        )

Retry behaviour:
    - Retries on 429 and server-side 5xx only.
    - 4xx errors other than 429 are NOT retried -- they indicate caller bugs
      (bad credentials, bad policy ID) and should surface immediately.
    - On 429, the wait time is read from the ``x-ms-retry-after-ms`` or
      ``Retry-After`` response header. On 5xx, exponential backoff is used.
      A single wait callback handles both cases so there is no double-sleep.
"""

from __future__ import annotations

import asyncio
import os
from types import TracebackType
from typing import Any

import httpx
import msal
import structlog
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from models.source_models import IntuneDevice, PolicyDeviceStatus

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

_MANAGED_DEVICES_URL = (
    f"{_GRAPH_BASE}/deviceManagement/managedDevices"
    "?$select=id,deviceName,serialNumber,userPrincipalName,"
    "operatingSystem,osVersion,model"
)

_COMPLIANCE_POLICIES_URL = (
    f"{_GRAPH_BASE}/deviceManagement/deviceCompliancePolicies"
    "?$select=id,displayName"
)

# Windows Update Rings live under a separate resource type -- NOT under
# deviceCompliancePolicies. Querying compliance policies for an Update Ring
# display name will always return nothing.
_UPDATE_RINGS_URL = (
    f"{_GRAPH_BASE}/deviceManagement/windowsUpdateForBusinessConfigurations"
    "?$select=id,displayName"
)

# Gentle delay between sequential page requests within a single method call.
# At 100 devices/page, 25-30 total pages are well below the per-app quota
# (2,000 req/20 sec), but this keeps us friendly to other tenant consumers.
_INTER_PAGE_DELAY_SECONDS: float = 0.1


def _device_statuses_url(policy_id: str) -> str:
    return (
        f"{_GRAPH_BASE}/deviceManagement/deviceCompliancePolicies"
        f"/{policy_id}/deviceStatuses"
        "?$select=id,deviceDisplayName,status,userPrincipalName"
    )


def _update_ring_statuses_url(ring_id: str) -> str:
    return (
        f"{_GRAPH_BASE}/deviceManagement/windowsUpdateForBusinessConfigurations"
        f"/{ring_id}/deviceStatuses"
        "?$select=id,deviceDisplayName,status"
    )


def _parse_retry_after(response: httpx.Response) -> float:
    """Extract retry delay from Microsoft throttling response headers.

    ``x-ms-retry-after-ms`` (milliseconds) takes precedence over
    ``Retry-After`` (seconds) when both are present, per Graph API docs.
    Falls back to 30 seconds if neither header is present or parseable.
    """
    ms_header = response.headers.get("x-ms-retry-after-ms")
    if ms_header:
        try:
            return float(ms_header) / 1000.0
        except ValueError:
            pass

    retry_header = response.headers.get("Retry-After")
    if retry_header:
        try:
            return float(retry_header)
        except ValueError:
            pass

    return 30.0


def _is_retryable(exc: BaseException) -> bool:
    """Return True only for 429 and server-side 5xx errors.

    4xx errors other than 429 (e.g. 401 bad token, 403 forbidden, 404 bad policy ID)
    are caller bugs and should fail immediately rather than burning retry budget.
    """
    return (
        isinstance(exc, httpx.HTTPStatusError)
        and exc.response.status_code in {429, 500, 502, 503, 504}
    )


class _GraphAPIWait:
    """Tenacity wait strategy for Microsoft Graph API retries.

    On 429: respect the server's Retry-After or x-ms-retry-after-ms header.
    On 5xx: fall back to standard exponential backoff (min 2s, max 60s).

    Intentionally does NOT subclass wait_base -- tenacity accepts any callable
    (RetryCallState) -> float as a wait strategy. Avoiding the inheritance removes
    coupling to tenacity internals that changed in v9.0 and broke deployments.
    """

    _exp = wait_exponential(multiplier=1, min=2, max=60)

    def __call__(self, retry_state: RetryCallState) -> float:
        exc = retry_state.outcome.exception()
        if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
            return _parse_retry_after(exc.response)
        return self._exp(retry_state)


class IntuneClient:
    """Fetches device inventory and compliance policy states from Microsoft Intune.

    Must be used as an async context manager. A single ``httpx.AsyncClient``
    is created on entry and closed on exit, shared across all method calls.
    This allows concurrent method calls via ``asyncio.gather`` to benefit from
    connection pooling to the same Graph API host.

    Requires three env vars:
        - ``INTUNE_TENANT_ID``
        - ``INTUNE_CLIENT_ID``
        - ``INTUNE_CLIENT_SECRET``

    The Azure AD App Registration must have both Application permissions granted
    with admin consent:
        - ``DeviceManagementManagedDevices.Read.All``
        - ``DeviceManagementConfiguration.Read.All``
    """

    def __init__(self) -> None:
        self._tenant_id: str = self._require_env("INTUNE_TENANT_ID")
        self._client_id: str = self._require_env("INTUNE_CLIENT_ID")
        self._client_secret: str = self._require_env("INTUNE_CLIENT_SECRET")

        authority = f"https://login.microsoftonline.com/{self._tenant_id}"
        self._msal_app: msal.ConfidentialClientApplication = (
            msal.ConfidentialClientApplication(
                client_id=self._client_id,
                client_credential=self._client_secret,
                authority=authority,
            )
        )
        # The /.default scope means "all statically-configured Application permissions"
        self._scopes: list[str] = ["https://graph.microsoft.com/.default"]
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "IntuneClient":
        self._http = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ── Public API ──────────────────────────────────────────────────────────────

    async def fetch_all_devices(self) -> list[IntuneDevice]:
        """Paginate through all managed devices across all enrolled platforms.

        Follows ``@odata.nextLink`` until exhausted. No ``$filter`` is applied --
        all platforms are returned and filtered downstream in the normalizer.
        """
        devices: list[IntuneDevice] = []
        url: str | None = _MANAGED_DEVICES_URL
        page_num = 0

        while url is not None:
            page_num += 1
            data = await self._fetch_page(url, self._auth_headers())
            raw_devices: list[dict[str, Any]] = data.get("value", [])

            for raw in raw_devices:
                device = self._parse_device(raw)
                if device is not None:
                    devices.append(device)

            logger.debug(
                "intune_page_fetched",
                page=page_num,
                records_on_page=len(raw_devices),
                total_so_far=len(devices),
            )

            url = data.get("@odata.nextLink")
            if url is not None:
                await asyncio.sleep(_INTER_PAGE_DELAY_SECONDS)

        logger.info("intune_devices_fetched", total=len(devices))
        return devices

    async def resolve_policy_ids(
        self,
        policy_names: dict[str, str],
    ) -> dict[str, str]:
        """Resolve customer-configured policy display names to Intune policy GUIDs.

        Fetches all compliance policies from the tenant and does case-insensitive
        exact matching against the provided display names. Logs a WARNING for
        each name that has no match -- those check types will be omitted from all
        payloads for this run (non-fatal by design).

        Args:
            policy_names: {check_type: display_name} for each configured policy.

        Returns:
            {check_type: policy_id} for display names that matched.
        """
        if not policy_names:
            return {}

        all_policies: list[dict[str, Any]] = []
        url: str | None = _COMPLIANCE_POLICIES_URL

        while url is not None:
            data = await self._fetch_page(url, self._auth_headers())
            all_policies.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            if url is not None:
                await asyncio.sleep(_INTER_PAGE_DELAY_SECONDS)

        # Build a lowercased name -> id lookup for O(1) matching
        policy_id_by_name: dict[str, str] = {
            p["displayName"].lower(): p["id"]
            for p in all_policies
            if p.get("displayName") and p.get("id")
        }

        resolved: dict[str, str] = {}
        for check_type, display_name in policy_names.items():
            policy_id = policy_id_by_name.get(display_name.lower())
            if policy_id:
                resolved[check_type] = policy_id
                logger.info(
                    "policy_resolved",
                    check_type=check_type,
                    display_name=display_name,
                    policy_id=policy_id,
                )
            else:
                logger.warning(
                    "policy_not_found_in_intune",
                    check_type=check_type,
                    display_name=display_name,
                    hint="Check that the display name matches exactly (case-insensitive) in Intune",
                )

        return resolved

    async def fetch_policy_device_statuses(
        self,
        policy_id: str,
        check_type: str,
    ) -> list[PolicyDeviceStatus]:
        """Fetch all device compliance states for a single compliance policy.

        Each status record's ``id`` field is a compound key of the form
        ``{managedDeviceId}_{userId}``. We split on ``_`` to extract the
        managedDeviceId, which is the join key to ``IntuneDevice.id``.

        IMPORTANT: Verify the id format during smoke testing -- some tenant
        configurations may use a different separator or field ordering.

        Args:
            policy_id:   The compliance policy GUID from ``resolve_policy_ids()``.
            check_type:  The Drata field name (e.g. ``"screenLockEnabled"``).
                         Used only for logging.

        Returns:
            Flat list of all device status records for this policy (all pages).
        """
        statuses: list[PolicyDeviceStatus] = []
        url: str | None = _device_statuses_url(policy_id)
        page_num = 0

        while url is not None:
            page_num += 1
            data = await self._fetch_page(url, self._auth_headers())
            raw_statuses: list[dict[str, Any]] = data.get("value", [])

            for raw in raw_statuses:
                status = self._parse_policy_status(raw, check_type)
                if status is not None:
                    statuses.append(status)

            logger.debug(
                "policy_status_page_fetched",
                check_type=check_type,
                policy_id=policy_id,
                page=page_num,
                records_on_page=len(raw_statuses),
                total_so_far=len(statuses),
            )

            url = data.get("@odata.nextLink")
            if url is not None:
                await asyncio.sleep(_INTER_PAGE_DELAY_SECONDS)

        logger.info(
            "policy_statuses_fetched",
            check_type=check_type,
            policy_id=policy_id,
            total=len(statuses),
        )
        return statuses

    async def resolve_update_ring_ids(
        self,
        ring_names: dict[str, str],
    ) -> dict[str, str]:
        """Resolve Windows Update Ring display names to GUIDs.

        Queries ``/deviceManagement/windowsUpdateForBusinessConfigurations`` --
        a separate resource type from compliance policies. Update Ring names are
        never returned by ``resolve_policy_ids`` and vice versa.

        Args:
            ring_names: {check_type: display_name} for each configured ring.

        Returns:
            {check_type: ring_id} for display names that matched.
        """
        if not ring_names:
            return {}

        all_rings: list[dict[str, Any]] = []
        url: str | None = _UPDATE_RINGS_URL

        while url is not None:
            data = await self._fetch_page(url, self._auth_headers())
            all_rings.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            if url is not None:
                await asyncio.sleep(_INTER_PAGE_DELAY_SECONDS)

        ring_id_by_name: dict[str, str] = {
            r["displayName"].lower(): r["id"]
            for r in all_rings
            if r.get("displayName") and r.get("id")
        }

        resolved: dict[str, str] = {}
        for check_type, display_name in ring_names.items():
            ring_id = ring_id_by_name.get(display_name.lower())
            if ring_id:
                resolved[check_type] = ring_id
                logger.info(
                    "update_ring_resolved",
                    check_type=check_type,
                    display_name=display_name,
                    ring_id=ring_id,
                )
            else:
                logger.warning(
                    "update_ring_not_found",
                    check_type=check_type,
                    display_name=display_name,
                    hint="Check that the display name matches exactly (case-insensitive) in Intune",
                )

        return resolved

    async def fetch_update_ring_device_statuses(
        self,
        ring_id: str,
        check_type: str,
    ) -> list[PolicyDeviceStatus]:
        """Fetch all device statuses for a Windows Update Ring.

        Queries ``/deviceManagement/windowsUpdateForBusinessConfigurations/{id}/deviceStatuses``.
        The status vocabulary differs from compliance policies:
            "succeeded"     -- ring config applied; auto-updates are managed
            "failed"        -- ring config failed to apply
            "error"         -- transient error; indeterminate
            "conflict"      -- policy conflict; indeterminate
            "notApplicable" -- device not applicable; indeterminate
            "pending"       -- awaiting policy delivery; indeterminate
            "unknown"       -- indeterminate

        IMPORTANT: Verify the ``id`` compound-key format during smoke testing.
        Expected: ``{managedDeviceId}_{userId}`` (same as compliance policies),
        but confirm against a real tenant response.

        Args:
            ring_id:    The Update Ring GUID from ``resolve_update_ring_ids()``.
            check_type: The Drata field name (``"autoUpdateEnabled"``).
                        Used only for logging.

        Returns:
            Flat list of all device status records for this ring (all pages).
        """
        statuses: list[PolicyDeviceStatus] = []
        url: str | None = _update_ring_statuses_url(ring_id)
        page_num = 0

        while url is not None:
            page_num += 1
            data = await self._fetch_page(url, self._auth_headers())
            raw_statuses: list[dict[str, Any]] = data.get("value", [])

            for raw in raw_statuses:
                status = self._parse_policy_status(raw, check_type)
                if status is not None:
                    statuses.append(status)

            logger.debug(
                "update_ring_status_page_fetched",
                check_type=check_type,
                ring_id=ring_id,
                page=page_num,
                records_on_page=len(raw_statuses),
                total_so_far=len(statuses),
            )

            url = data.get("@odata.nextLink")
            if url is not None:
                await asyncio.sleep(_INTER_PAGE_DELAY_SECONDS)

        logger.info(
            "update_ring_statuses_fetched",
            check_type=check_type,
            ring_id=ring_id,
            total=len(statuses),
        )
        return statuses

    # ── Internal helpers ────────────────────────────────────────────────────────

    @property
    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError(
                "IntuneClient must be used as an async context manager: "
                "'async with IntuneClient() as intune: ...'"
            )
        return self._http

    def _auth_headers(self) -> dict[str, str]:
        """Build auth headers, acquiring a fresh token via MSAL if needed."""
        return {
            "Authorization": f"Bearer {self._acquire_token()}",
            "Accept": "application/json",
        }

    def _acquire_token(self) -> str:
        """Get a valid bearer token from MSAL's cache, or acquire a new one.

        MSAL's ``acquire_token_silent`` handles cache lookup and proactive
        refresh -- we never store the token string directly.
        """
        result = self._msal_app.acquire_token_silent(
            scopes=self._scopes,
            account=None,
        )

        if not result:
            result = self._msal_app.acquire_token_for_client(scopes=self._scopes)

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "unknown"))
            raise RuntimeError(f"Intune token acquisition failed: {error}")

        return result["access_token"]

    @retry(
        stop=stop_after_attempt(5),
        wait=_GraphAPIWait(),
        retry=retry_if_exception(_is_retryable),
        before_sleep=lambda retry_state: structlog.get_logger().warning(
            "intune_request_retry",
            attempt=retry_state.attempt_number,
            wait=retry_state.next_action.sleep if retry_state.next_action else 0,
        ),
    )
    async def _fetch_page(
        self,
        url: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Fetch a single page from the Graph API with retry on 429/5xx.

        Raises ``httpx.HTTPStatusError`` for any non-2xx response so that
        tenacity can evaluate whether to retry. 4xx errors other than 429
        are not retried -- they indicate a caller bug (bad credentials, bad
        policy ID) and should surface immediately with a clear error.
        """
        response = await self._client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _parse_device(raw: dict[str, Any]) -> IntuneDevice | None:
        """Parse a raw Graph API device record into an ``IntuneDevice``.

        Returns ``None`` if the required ``id`` field is absent -- shouldn't
        happen with the ``$select`` filter but we don't trust external APIs.
        """
        device_id = raw.get("id")
        if not device_id:
            logger.warning("intune_device_missing_id", raw_keys=list(raw.keys()))
            return None

        return IntuneDevice(
            id=device_id,
            device_name=raw.get("deviceName", ""),
            serial_number=raw.get("serialNumber"),
            user_principal_name=raw.get("userPrincipalName"),
            operating_system=raw.get("operatingSystem", ""),
            os_version=raw.get("osVersion", ""),
            model=raw.get("model"),
        )

    @staticmethod
    def _parse_policy_status(
        raw: dict[str, Any],
        check_type: str,
    ) -> PolicyDeviceStatus | None:
        """Parse a raw ``deviceStatuses`` record into a ``PolicyDeviceStatus``.

        The ``id`` field format is ``"{managedDeviceId}_{userId}"``. We split
        on the first ``_`` to extract the managedDeviceId join key. GUIDs use
        hyphens as separators, never underscores, so this split is unambiguous.

        Returns ``None`` if the ``id`` or ``status`` field is absent.
        """
        raw_id = raw.get("id", "")
        if not raw_id:
            logger.warning(
                "policy_status_missing_id",
                check_type=check_type,
                raw_keys=list(raw.keys()),
            )
            return None

        status = raw.get("status", "")
        if not status:
            logger.warning(
                "policy_status_missing_status",
                check_type=check_type,
                raw_id=raw_id,
            )
            return None

        # "{managedDeviceId}_{userId}" -- take the left segment.
        # GUIDs contain only hex chars and hyphens, never underscores.
        device_id = raw_id.split("_")[0] if "_" in raw_id else raw_id

        return PolicyDeviceStatus(
            device_id=device_id,
            status=status,
            device_display_name=raw.get("deviceDisplayName", ""),
        )

    @staticmethod
    def _require_env(name: str) -> str:
        """Read a required environment variable or raise loudly at init time."""
        value = os.environ.get(name)
        if not value:
            raise EnvironmentError(
                f"Required environment variable '{name}' is not set or empty. "
                f"See .env.example for the full list."
            )
        return value
