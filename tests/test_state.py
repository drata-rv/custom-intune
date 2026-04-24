"""Tests for core/state.py -- hash computation and StateManager lifecycle."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.state import StateManager, compute_payload_hash


# ── compute_payload_hash ──────────────────────────────────────────────────────

class TestComputePayloadHash:

    def test_deterministic(self):
        payload = {"externalId": "abc", "platformName": "WINDOWS", "screenLockEnabled": True}
        assert compute_payload_hash(payload) == compute_payload_hash(payload)

    def test_order_independent(self):
        """Dict insertion order must not affect the hash -- canonical form uses sorted keys."""
        p1 = {"a": 1, "b": 2}
        p2 = {"b": 2, "a": 1}
        assert compute_payload_hash(p1) == compute_payload_hash(p2)

    def test_different_values_produce_different_hash(self):
        p1 = {"externalId": "x", "encryptionEnabled": True}
        p2 = {"externalId": "x", "encryptionEnabled": False}
        assert compute_payload_hash(p1) != compute_payload_hash(p2)

    def test_extra_field_changes_hash(self):
        p1 = {"externalId": "x"}
        p2 = {"externalId": "x", "platformName": "WINDOWS"}
        assert compute_payload_hash(p1) != compute_payload_hash(p2)

    def test_hash_is_64_hex_chars(self):
        """SHA-256 output is always 256 bits = 64 hex characters."""
        h = compute_payload_hash({"x": 1})
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_nested_dict_is_stable(self):
        p = {"meta": {"source": "intune", "version": 1}}
        assert compute_payload_hash(p) == compute_payload_hash(p)


# ── StateManager ──────────────────────────────────────────────────────────────

@pytest.fixture
def state_file(tmp_path: Path) -> Path:
    return tmp_path / "drata_state.json"


class TestStateManager:

    def test_load_no_file_is_noop(self, state_file: Path):
        sm = StateManager(state_file)
        sm.load()   # must not raise
        assert sm.is_changed("any-id", {"x": 1}) is True

    def test_is_changed_returns_true_for_new_device(self, state_file: Path):
        sm = StateManager(state_file)
        sm.load()
        assert sm.is_changed("new-guid", {"platformName": "WINDOWS"}) is True

    def test_is_changed_returns_false_after_record_success(self, state_file: Path):
        sm = StateManager(state_file)
        sm.load()
        payload = {"externalId": "guid-1", "platformName": "WINDOWS"}
        sm.record_success("guid-1", payload)
        assert sm.is_changed("guid-1", payload) is False

    def test_is_changed_returns_true_after_field_modified(self, state_file: Path):
        sm = StateManager(state_file)
        sm.load()
        payload_v1 = {"externalId": "guid-1", "screenLockEnabled": True}
        payload_v2 = {"externalId": "guid-1", "screenLockEnabled": False}
        sm.record_success("guid-1", payload_v1)
        assert sm.is_changed("guid-1", payload_v2) is True

    def test_persist_then_reload_round_trip(self, state_file: Path):
        """State written to disk must be readable on the next run."""
        sm1 = StateManager(state_file)
        sm1.load()
        payload = {
            "externalId": "guid-rt",
            "platformName": "MACOS",
            "encryptionEnabled": True,
        }
        sm1.record_success("guid-rt", payload)
        sm1.persist()

        sm2 = StateManager(state_file)
        sm2.load()
        assert sm2.is_changed("guid-rt", payload) is False

    def test_persist_atomic_write(self, state_file: Path):
        """After persist(), the .tmp file must not remain."""
        sm = StateManager(state_file)
        sm.load()
        sm.record_success("x", {"a": 1})
        sm.persist()

        tmp = state_file.with_suffix(".tmp")
        assert not tmp.exists(), ".tmp file should be gone after os.replace()"
        assert state_file.exists()

    def test_corrupt_state_file_treated_as_first_run(self, state_file: Path):
        state_file.write_text("{{invalid json{{", encoding="utf-8")
        sm = StateManager(state_file)
        sm.load()   # must not raise
        assert sm.is_changed("any-id", {"x": 1}) is True

    def test_record_success_does_not_write_to_disk(self, state_file: Path):
        """record_success is in-memory only -- persist() is what writes to disk."""
        sm = StateManager(state_file)
        sm.load()
        sm.record_success("guid-x", {"platformName": "LINUX"})
        assert not state_file.exists()

    def test_persist_stores_last_pushed_timestamp(self, state_file: Path):
        sm = StateManager(state_file)
        sm.load()
        sm.record_success("guid-ts", {"p": 1})
        sm.persist()

        raw = json.loads(state_file.read_text())
        assert "last_pushed" in raw["guid-ts"]
        assert raw["guid-ts"]["last_pushed"].endswith("Z") or "+" in raw["guid-ts"]["last_pushed"]
