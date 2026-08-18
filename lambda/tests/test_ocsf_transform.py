"""Unit tests for transform.ocsf — Idira AuditDto → OCSF Detection Finding (2004)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from transform.ocsf import to_ocsf, OCSF_VERSION

FIXTURES = Path(__file__).parent / "fixtures"

_AWS_ACCOUNT = "123456789012"
_AWS_REGION = "us-east-1"


@pytest.fixture
def login_event() -> dict:
    return json.loads((FIXTURES / "cyberark_event.json").read_text())


@pytest.fixture
def failure_event() -> dict:
    return json.loads((FIXTURES / "cyberark_event_failure.json").read_text())


@pytest.fixture
def minimal_event() -> dict:
    return {"uuid": "min-uuid", "timestamp": 1000, "actionType": "Login", "auditType": "Success"}


class TestClassMapping:
    def test_all_events_map_to_detection_finding(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["class_uid"] == 2004
        assert result["category_uid"] == 2

    def test_activity_is_create(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["activity_id"] == 1
        assert result["activity_name"] == "Create"

    def test_type_uid(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["type_uid"] == 2004 * 100 + 1


class TestSeverityMapping:
    @pytest.mark.parametrize("audit_type,expected_id,expected_label", [
        ("Success", 1, "Informational"),
        ("Info", 1, "Informational"),
        ("Failure", 3, "Medium"),
        ("Failure reason", 3, "Medium"),
        ("Timeout or URL not found", 4, "High"),
        ("System Error", 5, "Critical"),
        ("Unknown", 0, "Unknown"),
    ])
    def test_severity(self, audit_type, expected_id, expected_label, login_event):
        event = {**login_event, "auditType": audit_type}
        result = to_ocsf(event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["severity_id"] == expected_id
        assert result["severity"] == expected_label


class TestMetadata:
    def test_ocsf_version(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["metadata"]["version"] == OCSF_VERSION

    def test_profiles(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["metadata"]["profiles"] == ["cloud", "datetime"]

    def test_product_vendor(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["metadata"]["product"]["vendor_name"] == "Palo Alto Networks"
        assert result["metadata"]["product"]["name"] == "Idira Audit"

    def test_product_uid_is_integration_arn(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["metadata"]["product"]["uid"] == f"arn:aws:securityhub:{_AWS_REGION}::productv2/e74c7eec-1d4f-4601-98cd-f22ffd268b0f"

    def test_reserved_fields_not_set(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert "uid" not in result["metadata"]
        assert "status" not in result
        assert "status_id" not in result


class TestFindingInfo:
    def test_uid_is_event_uuid(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["finding_info"]["uid"] == login_event["uuid"]

    def test_title_contains_action_and_app(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert "Login" in result["finding_info"]["title"]
        assert "EPM" in result["finding_info"]["title"]

    def test_created_time_from_event(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["finding_info"]["created_time"] == login_event["timestamp"]

    def test_modified_time_equals_time(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["time"] == result["finding_info"]["modified_time"]

    def test_analytic_contains_audit_code(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        analytic = result["finding_info"]["analytic"]
        assert analytic["uid"] == login_event["auditCode"]
        assert login_event["applicationCode"] in analytic["name"]


class TestCloud:
    def test_provider_is_aws(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["cloud"]["provider"] == "AWS"

    def test_account_uid(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["cloud"]["account"]["uid"] == _AWS_ACCOUNT

    def test_region(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["cloud"]["region"] == _AWS_REGION


class TestResources:
    def test_resource_type(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["resources"][0]["type"] == "AWS::::Account"

    def test_resource_owner_account(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["resources"][0]["owner"]["account"]["uid"] == _AWS_ACCOUNT


class TestUnmapped:
    def test_null_values_excluded(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert "safe" not in result.get("unmapped", {})
        assert "cloudProvider" not in result.get("unmapped", {})

    def test_present_values_included(self, failure_event):
        result = to_ocsf(failure_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["unmapped"]["safe"] == "LinuxServers"
        assert result["unmapped"]["cloudProvider"] == "AWS"
        assert result["unmapped"]["targetPlatform"] == "UnixSSH"


class TestEdgeCases:
    def test_minimal_event_does_not_raise(self, minimal_event):
        result = to_ocsf(minimal_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert result["class_uid"] == 2004

    def test_message_preserved(self, login_event):
        result = to_ocsf(login_event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert login_event["message"] in result["message"]

    def test_deterministic_uid_without_uuid(self):
        event = {"actionType": "Login", "auditType": "Success", "timestamp": 1000, "applicationCode": "PAM", "auditCode": "X"}
        r1 = to_ocsf(event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        r2 = to_ocsf(event, aws_account_id=_AWS_ACCOUNT, aws_region=_AWS_REGION)
        assert r1["finding_info"]["uid"] == r2["finding_info"]["uid"]
        assert len(r1["finding_info"]["uid"]) == 64  # SHA-256 hex
