"""State management for SHA-256 delta detection between Drata publisher runs.

The state file (``drata_state.json``) maps each ``externalId`` to its last
successfully pushed payload hash. On subsequent runs, only devices whose
payload hash has changed are re-pushed -- reducing a 2,500-device run from
~6 minutes to seconds.

All disk writes use the atomic ``.tmp -> os.replace()`` pattern to prevent
corruption if the process is killed mid-write.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)


def compute_payload_hash(payload: dict[str, Any]) -> str:
    """SHA-256 of the canonical JSON serialization of a Drata payload.

    Canonical form: keys sorted alphabetically, no extra whitespace.
    This ensures that logically identical payloads always produce the same hash
    regardless of dict insertion order.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class StateManager:
    """Manages the persistent hash state used for delta detection.

    Lifecycle:
        1. ``load()`` -- read ``drata_state.json`` (or start empty on first run).
        2. ``is_changed()`` -- check if a payload differs from the last push.
        3. ``record_success()`` -- update in-memory state after a successful push.
        4. ``persist()`` -- atomically write the updated state to disk.

    The ``payload`` field in each state entry stores the last successfully pushed
    payload verbatim -- this enables manual replay of a specific device without
    re-running the full pipeline.
    """

    def __init__(self, path: Path) -> None:
        self._path: Path = path
        self._state: dict[str, dict[str, Any]] = {}

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> None:
        """Load ``drata_state.json`` if it exists. No-op on first run."""
        if not self._path.exists():
            logger.info("state_file_not_found", path=str(self._path), note="first run")
            return

        try:
            raw = self._path.read_text(encoding="utf-8")
            self._state = json.loads(raw)
            logger.info("state_loaded", device_count=len(self._state))
        except (json.JSONDecodeError, OSError) as exc:
            # Corrupted state is non-fatal -- treat as first run. Every device
            # will be re-pushed, which is safe because Drata upserts.
            logger.warning(
                "state_file_corrupt",
                path=str(self._path),
                error=str(exc),
                action="treating as first run",
            )
            self._state = {}

    def is_changed(self, external_id: str, payload: dict[str, Any]) -> bool:
        """Return ``True`` if the payload hash differs from the stored hash,
        or if there is no prior entry for this ``externalId``."""
        current_hash = compute_payload_hash(payload)
        prior = self._state.get(external_id)
        if prior is None:
            return True
        return prior.get("hash") != current_hash

    def record_success(self, external_id: str, payload: dict[str, Any]) -> None:
        """Update in-memory state after a successful Drata push.

        Does NOT write to disk -- call ``persist()`` after all pushes complete.
        """
        self._state[external_id] = {
            "hash": compute_payload_hash(payload),
            "last_pushed": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        }

    def persist(self) -> None:
        """Atomically write the state to disk via ``.tmp -> os.replace()``.

        This guarantees that a crash mid-write leaves the prior state file
        intact rather than producing a corrupt partial write.
        """
        tmp_path = self._path.with_suffix(".tmp")
        try:
            tmp_path.write_text(
                json.dumps(self._state, indent=2),
                encoding="utf-8",
            )
            os.replace(tmp_path, self._path)
            logger.info("state_persisted", device_count=len(self._state))
        except OSError as exc:
            logger.error("state_persist_failed", error=str(exc))
            raise
