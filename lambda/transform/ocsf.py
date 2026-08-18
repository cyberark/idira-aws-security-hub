"""Transform Idira Audit events to OCSF Detection Finding (class_uid 2004).

Produces findings compliant with the Security Hub BatchImportFindingsV2 API
using OCSF schema version 1.8.0.

OCSF class used:
  2004 - Detection Finding (all Idira audit events)

Severity mapping (from Idira auditType):
  Success / Info            -> 1  Informational
  Failure / Failure reason  -> 3  Medium
  Timeout or URL not found  -> 4  High
  System Error              -> 5  Critical

Reference:
  https://schema.ocsf.io/1.8.0/
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

OCSF_VERSION = "1.8.0"
_CLASS_UID = 2004
_CATEGORY_UID = 2

_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "Success":                  (1, "Informational"),
    "Info":                     (1, "Informational"),
    "Failure":                  (3, "Medium"),
    "Failure reason":           (3, "Medium"),
    "Timeout or URL not found": (4, "High"),
    "System Error":             (5, "Critical"),
}
_DEFAULT_SEVERITY: tuple[int, str] = (0, "Unknown")


def _generate_finding_uid(event: dict[str, Any]) -> str:
    """Generate a deterministic finding_info.uid from event properties."""
    uuid = event.get("uuid", "")
    if uuid:
        return uuid
    composite = f"{event.get('applicationCode', '')}:{event.get('auditCode', '')}:{event.get('timestamp', '')}"
    return hashlib.sha256(composite.encode()).hexdigest()


def _ts_to_epoch_ms(event: dict[str, Any]) -> int:
    """Get timestamp as epoch milliseconds from the event."""
    ts = event.get("timestamp", 0)
    if ts:
        return ts
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def to_ocsf(
    event: dict[str, Any],
    aws_account_id: str | None = None,
    aws_region: str | None = None,
    product_uid: str | None = None,
) -> dict[str, Any]:
    """Convert a single Idira AuditDto to an OCSF Detection Finding for BatchImportFindingsV2.

    Args:
        event: Raw AuditDto from the Idira SIEM results API.
        aws_account_id: 12-digit AWS account ID (required for findingsv2).
        aws_region: AWS region string (required for findingsv2).
        product_uid: Registered product ARN from Security Hub onboarding.

    Returns:
        OCSF Detection Finding dict compliant with BatchImportFindingsV2.
    """
    audit_type: str = event.get("auditType", "")
    action_type: str = event.get("actionType", "")
    app_code: str = event.get("applicationCode", "unknown")

    severity_id, severity = _SEVERITY_MAP.get(audit_type, _DEFAULT_SEVERITY)

    ts_ms = _ts_to_epoch_ms(event)
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

    modified_time = now_ms
    created_time = ts_ms

    finding_uid = _generate_finding_uid(event)

    activity_id = 1
    activity_name = "Create"
    type_uid = _CLASS_UID * 100 + activity_id

    title = f"Idira Audit: {action_type or 'Event'} [{app_code}]"
    if len(title) > 2048:
        title = title[:2048]

    message = event.get("message", "")
    description = message or f"Idira {app_code} audit event: {action_type}"

    if product_uid is None and aws_region:
        product_uid = f"arn:aws:securityhub:{aws_region}::productv2/e74c7eec-1d4f-4601-98cd-f22ffd268b0f"

    finding: dict[str, Any] = {
        "class_uid": _CLASS_UID,
        "category_uid": _CATEGORY_UID,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": type_uid,
        "severity_id": severity_id,
        "severity": severity,
        "time": modified_time,
        "message": description,
        "metadata": {
            "version": OCSF_VERSION,
            "profiles": ["cloud", "datetime"],
            "product": {
                "name": "Idira Audit",
                "vendor_name": "Palo Alto Networks",
            },
        },
        "finding_info": {
            "uid": finding_uid,
            "title": title,
            "types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "created_time": created_time,
            "modified_time": modified_time,
            "desc": description,
            "analytic": {
                "name": f"Idira/{app_code}/{event.get('auditCode', 'unknown')}",
                "uid": event.get("auditCode", ""),
                "type_id": 1,
            },
        },
        "confidence_id": 3,
        "resources": [
            {
                "uid": f"arn:aws:iam::{aws_account_id or '000000000000'}:root",
                "type": "AWS::::Account",
                "cloud_partition": "aws",
                "region": aws_region or "us-east-1",
                "owner": {
                    "account": {
                        "uid": aws_account_id or "000000000000",
                    }
                },
            }
        ],
        "cloud": {
            "provider": "AWS",
            "account": {
                "uid": aws_account_id or "000000000000",
            },
            "region": aws_region or "us-east-1",
        },
    }

    if product_uid:
        finding["metadata"]["product"]["uid"] = product_uid


    unmapped = _build_unmapped(event)
    if unmapped:
        finding["unmapped"] = unmapped

    return finding


def _build_unmapped(event: dict[str, Any]) -> dict[str, Any]:
    """Capture Idira-specific fields not covered by OCSF Detection Finding fields."""
    keys = (
        "tenantId",
        "applicationCode",
        "auditCode",
        "auditType",
        "actionType",
        "component",
        "serviceName",
        "accessMethod",
        "accountId",
        "accountName",
        "username",
        "userId",
        "identityType",
        "sessionId",
        "source",
        "target",
        "command",
        "safe",
        "targetPlatform",
        "targetAccount",
        "cloudProvider",
        "correlationId",
    )
    return {k: event[k] for k in keys if event.get(k) is not None}
