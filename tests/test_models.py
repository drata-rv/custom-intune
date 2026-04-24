"""Tests for models/drata_models.py -- Pydantic schema validation and serialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from models.drata_models import PLATFORM_MAP, AgentPlatformEnum, DrataDevicePayload


# ── Minimal valid payload factory ─────────────────────────────────────────────

def _minimal(**overrides) -> dict:
    base = {
        "personnelId": "email:user@example.com",
        "platformName": "WINDOWS",
        "platformVersion": "10.0.19045.3930",
    }
    base.update(overrides)
    return base


# ── PLATFORM_MAP completeness ──────────────────────────────────────────────────

class TestPlatformMap:
    def test_all_drata_platforms_reachable(self):
        """Every commonly-used Drata platform must be reachable via PLATFORM_MAP."""
        reachable = set(PLATFORM_MAP.values())
        required = {"WINDOWS", "MACOS", "LINUX", "ANDROID"}
        assert required.issubset(reachable)

    def test_no_unsupported_platforms_in_map(self):
        """Every value in PLATFORM_MAP must be a platform Drata actually supports."""
        supported: set[AgentPlatformEnum] = {"WINDOWS", "MACOS", "LINUX", "UNIX", "ANDROID"}
        for key, value in PLATFORM_MAP.items():
            assert value in supported, (
                f"PLATFORM_MAP['{key}'] = '{value}' is not a valid Drata platform"
            )


# ── DrataDevicePayload validation ─────────────────────────────────────────────

class TestDrataDevicePayloadValidation:

    def test_minimal_valid_payload(self):
        p = DrataDevicePayload(**_minimal())
        assert p.platformName == "WINDOWS"
        assert p.personnelId == "email:user@example.com"

    def test_all_compliance_fields_default_to_none(self):
        p = DrataDevicePayload(**_minimal())
        assert p.screenLockEnabled is None
        assert p.autoUpdateEnabled is None
        assert p.passwordManagerEnabled is None
        assert p.encryptionEnabled is None
        assert p.antivirusEnabled is None

    def test_all_optional_identity_fields_default_to_none(self):
        p = DrataDevicePayload(**_minimal())
        assert p.externalId is None
        assert p.serialNumber is None
        assert p.alias is None
        assert p.model is None

    def test_personnelid_missing_email_prefix_raises(self):
        with pytest.raises(ValidationError, match="email:"):
            DrataDevicePayload(**_minimal(personnelId="user@example.com"))

    def test_personnelid_with_email_prefix_passes(self):
        p = DrataDevicePayload(**_minimal(personnelId="email:another@example.com"))
        assert p.personnelId == "email:another@example.com"

    @pytest.mark.parametrize("platform", ["WINDOWS", "MACOS", "LINUX", "UNIX", "ANDROID"])
    def test_all_valid_platforms_accepted(self, platform: str):
        p = DrataDevicePayload(**_minimal(platformName=platform))
        assert p.platformName == platform

    @pytest.mark.parametrize("bad_platform", ["WINDOWS_10", "Mac", "ios", "iPadOS", "", "UNKNOWN"])
    def test_invalid_platform_raises(self, bad_platform: str):
        with pytest.raises(ValidationError):
            DrataDevicePayload(**_minimal(platformName=bad_platform))

    def test_extra_fields_forbidden(self):
        """extra='forbid' ensures unexpected fields from API changes are caught immediately."""
        with pytest.raises(ValidationError):
            DrataDevicePayload(**_minimal(unknownField="surprise"))

    def test_alias_truncated_at_191_chars(self):
        p = DrataDevicePayload(**_minimal(alias="X" * 200))
        assert len(p.alias) == 191

    def test_model_truncated_at_191_chars(self):
        p = DrataDevicePayload(**_minimal(model="M" * 250))
        assert len(p.model) == 191

    def test_platform_version_truncated_at_191_chars(self):
        p = DrataDevicePayload(**_minimal(platformVersion="1.0." + "0" * 200))
        assert len(p.platformVersion) == 191

    def test_alias_under_191_not_truncated(self):
        name = "Normal Device Name"
        p = DrataDevicePayload(**_minimal(alias=name))
        assert p.alias == name

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            DrataDevicePayload(platformName="WINDOWS", platformVersion="10.0")  # type: ignore[call-arg]

    def test_compliance_fields_accept_true(self):
        p = DrataDevicePayload(**_minimal(
            screenLockEnabled=True,
            autoUpdateEnabled=True,
            passwordManagerEnabled=True,
            encryptionEnabled=True,
            antivirusEnabled=True,
        ))
        assert p.screenLockEnabled is True
        assert p.encryptionEnabled is True

    def test_compliance_fields_accept_false(self):
        """False is a valid and meaningful compliance value (confirmed noncompliant)."""
        p = DrataDevicePayload(**_minimal(
            screenLockEnabled=False,
            encryptionEnabled=False,
        ))
        assert p.screenLockEnabled is False
        assert p.encryptionEnabled is False


# ── to_drata_dict / omission rule ────────────────────────────────────────────

class TestToDrataDict:

    def test_none_compliance_fields_excluded(self):
        p = DrataDevicePayload(**_minimal())
        d = p.to_drata_dict()
        for field in (
            "screenLockEnabled", "autoUpdateEnabled", "passwordManagerEnabled",
            "encryptionEnabled", "antivirusEnabled",
        ):
            assert field not in d, f"'{field}' should be absent when None"

    def test_none_identity_fields_excluded(self):
        p = DrataDevicePayload(**_minimal())
        d = p.to_drata_dict()
        for field in ("externalId", "serialNumber", "alias", "model"):
            assert field not in d, f"'{field}' should be absent when None"

    def test_present_compliance_fields_included(self):
        p = DrataDevicePayload(**_minimal(
            encryptionEnabled=True,
            antivirusEnabled=True,
            screenLockEnabled=True,
        ))
        d = p.to_drata_dict()
        assert d["encryptionEnabled"] is True
        assert d["antivirusEnabled"] is True
        assert d["screenLockEnabled"] is True

    def test_false_compliance_value_is_included(self):
        """False must survive serialization -- it is confirmed non-compliance evidence."""
        p = DrataDevicePayload(**_minimal(
            screenLockEnabled=False,
            encryptionEnabled=False,
        ))
        d = p.to_drata_dict()
        assert "screenLockEnabled" in d
        assert d["screenLockEnabled"] is False
        assert "encryptionEnabled" in d
        assert d["encryptionEnabled"] is False

    def test_required_fields_always_present(self):
        d = DrataDevicePayload(**_minimal()).to_drata_dict()
        assert "personnelId" in d
        assert "platformName" in d
        assert "platformVersion" in d

    def test_serialization_is_json_compatible(self):
        """to_drata_dict() must produce JSON-serializable output."""
        import json
        p = DrataDevicePayload(**_minimal(
            externalId="guid-y",
            screenLockEnabled=True,
            autoUpdateEnabled=False,
        ))
        json.dumps(p.to_drata_dict())

    def test_partial_compliance_only_configured_fields_present(self):
        """Only explicitly set checks appear -- no accidental presence of other fields."""
        p = DrataDevicePayload(**_minimal(autoUpdateEnabled=True))
        d = p.to_drata_dict()
        assert "autoUpdateEnabled" in d
        assert "screenLockEnabled" not in d
        assert "encryptionEnabled" not in d
        assert "passwordManagerEnabled" not in d
        assert "antivirusEnabled" not in d
