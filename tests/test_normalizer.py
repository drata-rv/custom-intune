"""Tests for core/normalizer.py -- the most critical logic in the pipeline.

All tests are pure in-process: no HTTP calls, no file I/O, no env vars required.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.normalizer import (
    build_drata_payload,
    map_compliance_state,
    map_platform,
    normalize_hostname,
    normalize_serial,
)
from models.source_models import ComplianceState, IntuneDevice


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _intune(
    os: str = "Windows",
    serial: str | None = "SN-001",
    upn: str | None = "user@example.com",
) -> IntuneDevice:
    return IntuneDevice(
        id="guid-1234",
        device_name="PC-TEST",
        serial_number=serial,
        user_principal_name=upn,
        operating_system=os,
        os_version="10.0.19045.3930",
        model="ThinkPad T14",
    )


def _compliance(**kwargs: bool) -> ComplianceState:
    """Build a ComplianceState dict. Keyword args are check_type -> bool."""
    return dict(kwargs)


# ── normalize_serial ──────────────────────────────────────────────────────────

class TestNormalizeSerial:
    def test_strips_and_uppercases(self):
        assert normalize_serial(" abc123 ") == "ABC123"

    def test_already_upper_unchanged(self):
        assert normalize_serial("ABC123") == "ABC123"

    def test_none_returns_none(self):
        assert normalize_serial(None) is None

    def test_empty_string_returns_none(self):
        assert normalize_serial("") is None

    def test_whitespace_only_returns_none(self):
        assert normalize_serial("   ") is None

    def test_mixed_case_normalized(self):
        assert normalize_serial("Abc-XYZ") == "ABC-XYZ"


# ── normalize_hostname ────────────────────────────────────────────────────────

class TestNormalizeHostname:
    def test_strips_and_lowercases(self):
        assert normalize_hostname("  PC-01  ") == "pc-01"

    def test_none_returns_none(self):
        assert normalize_hostname(None) is None

    def test_empty_returns_none(self):
        assert normalize_hostname("") is None

    def test_already_lower_unchanged(self):
        assert normalize_hostname("server-01") == "server-01"


# ── map_platform ─────────────────────────────────────────────────────────────

class TestMapPlatform:
    @pytest.mark.parametrize("os_str,expected", [
        ("Windows",   "WINDOWS"),
        ("windows",   "WINDOWS"),
        ("WINDOWS",   "WINDOWS"),
        ("macOS",     "MACOS"),
        ("Mac OS X",  "MACOS"),
        ("Linux",     "LINUX"),
        ("linux",     "LINUX"),
        ("Android",   "ANDROID"),
    ])
    def test_exact_and_case_insensitive_matches(self, os_str: str, expected: str):
        assert map_platform(os_str) == expected

    @pytest.mark.parametrize("os_str", [
        "Ubuntu 22.04 LTS",
        "Ubuntu",
        "Debian 11",
        "RHEL 8",
    ])
    def test_linux_prefix_match(self, os_str: str):
        assert map_platform(os_str) == "LINUX"

    @pytest.mark.parametrize("os_str", [
        "iOS",
        "iPadOS",
        "iOS 17.0",
        "ChromeOS",
        "Unknown",
        "",
    ])
    def test_unsupported_returns_none(self, os_str: str):
        assert map_platform(os_str) is None


# ── map_compliance_state ──────────────────────────────────────────────────────

class TestMapComplianceState:

    def test_compliant_returns_true(self):
        assert map_compliance_state("compliant") is True

    def test_noncompliant_returns_false(self):
        """noncompliant is confirmed evidence -- must return False, not None."""
        assert map_compliance_state("noncompliant") is False

    @pytest.mark.parametrize("status", [
        "unknown",
        "notApplicable",
        "error",
        "conflict",
        "inGracePeriod",
    ])
    def test_indeterminate_states_return_none(self, status: str):
        assert map_compliance_state(status) is None

    def test_unexpected_status_returns_none(self):
        """Defensive: any unrecognized status string is treated as indeterminate."""
        assert map_compliance_state("someNewStatusFromMicrosoft") is None

    def test_case_sensitive_compliant(self):
        """Intune sends lowercase -- verify exact match, no accidental case folding."""
        assert map_compliance_state("Compliant") is None
        assert map_compliance_state("COMPLIANT") is None


# ── build_drata_payload ───────────────────────────────────────────────────────

class TestBuildDrataPayload:

    # ── Required field mapping ────────────────────────────────────────────────

    def test_personnelid_prefixed(self):
        payload = build_drata_payload(_intune(), {})
        assert payload.to_drata_dict()["personnelId"] == "email:user@example.com"

    def test_base_fields_from_intune(self):
        d = build_drata_payload(_intune(), {}).to_drata_dict()
        assert d["externalId"] == "guid-1234"
        assert d["platformName"] == "WINDOWS"
        assert d["platformVersion"] == "10.0.19045.3930"
        assert d["alias"] == "PC-TEST"
        assert d["model"] == "ThinkPad T14"

    # ── Platform mapping ──────────────────────────────────────────────────────

    def test_macos_platform_mapped(self):
        d = build_drata_payload(_intune(os="macOS"), {}).to_drata_dict()
        assert d["platformName"] == "MACOS"

    def test_linux_platform_mapped(self):
        d = build_drata_payload(_intune(os="Linux"), {}).to_drata_dict()
        assert d["platformName"] == "LINUX"

    def test_unsupported_platform_raises_value_error(self):
        with pytest.raises(ValueError, match="iPadOS"):
            build_drata_payload(_intune(os="iPadOS"), {})

    # ── Empty compliance -> all compliance fields absent ──────────────────────

    def test_no_compliance_fields_when_dict_empty(self):
        d = build_drata_payload(_intune(), {}).to_drata_dict()
        for field in (
            "screenLockEnabled", "autoUpdateEnabled", "passwordManagerEnabled",
            "encryptionEnabled", "antivirusEnabled",
        ):
            assert field not in d, f"'{field}' should be absent when compliance is empty"

    def test_no_false_for_absent_source(self):
        """The omission rule: empty compliance must not produce any False values."""
        d = build_drata_payload(_intune(), {}).to_drata_dict()
        assert False not in d.values()

    # ── Partial compliance -- only configured checks appear ───────────────────

    def test_single_check_present(self):
        d = build_drata_payload(_intune(), _compliance(screenLockEnabled=True)).to_drata_dict()
        assert d["screenLockEnabled"] is True
        assert "autoUpdateEnabled" not in d
        assert "encryptionEnabled" not in d

    def test_noncompliant_false_is_emitted(self):
        """Confirmed noncompliant is real evidence -- False must appear in the payload."""
        d = build_drata_payload(
            _intune(), _compliance(encryptionEnabled=False)
        ).to_drata_dict()
        assert "encryptionEnabled" in d
        assert d["encryptionEnabled"] is False

    # ── All five checks populated ─────────────────────────────────────────────

    def test_all_checks_compliant(self):
        compliance = _compliance(
            screenLockEnabled=True,
            autoUpdateEnabled=True,
            passwordManagerEnabled=True,
            encryptionEnabled=True,
            antivirusEnabled=True,
        )
        d = build_drata_payload(_intune(), compliance).to_drata_dict()
        assert d["screenLockEnabled"] is True
        assert d["autoUpdateEnabled"] is True
        assert d["passwordManagerEnabled"] is True
        assert d["encryptionEnabled"] is True
        assert d["antivirusEnabled"] is True

    def test_mixed_compliance_states(self):
        compliance = _compliance(
            screenLockEnabled=True,
            encryptionEnabled=False,   # confirmed noncompliant
            antivirusEnabled=True,
        )
        d = build_drata_payload(_intune(), compliance).to_drata_dict()
        assert d["screenLockEnabled"] is True
        assert d["encryptionEnabled"] is False
        assert d["antivirusEnabled"] is True
        assert "autoUpdateEnabled" not in d
        assert "passwordManagerEnabled" not in d

    # ── Platform-agnostic compliance ──────────────────────────────────────────

    def test_compliance_fields_on_macos(self):
        """Policy-based compliance is platform-agnostic -- all checks can appear on any OS."""
        d = build_drata_payload(
            _intune(os="macOS"),
            _compliance(encryptionEnabled=True, antivirusEnabled=True),
        ).to_drata_dict()
        assert d["platformName"] == "MACOS"
        assert d["encryptionEnabled"] is True
        assert d["antivirusEnabled"] is True

    def test_compliance_fields_on_linux(self):
        d = build_drata_payload(
            _intune(os="Linux"),
            _compliance(autoUpdateEnabled=False),
        ).to_drata_dict()
        assert d["platformName"] == "LINUX"
        assert d["autoUpdateEnabled"] is False

    # ── Missing UPN ──────────────────────────────────────────────────────────

    def test_missing_upn_raises_validation_error(self):
        device = IntuneDevice(
            id="guid-kiosk",
            device_name="KIOSK-01",
            serial_number=None,
            user_principal_name=None,
            operating_system="Windows",
            os_version="10.0",
            model=None,
        )
        with pytest.raises(ValidationError):
            build_drata_payload(device, {})
