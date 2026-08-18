"""Read Idira Audit downloaded report CSV files and return AuditDto-like dicts.

Column mapping from the report CSV to the AuditDto fields consumed by
:func:`transform.ocsf.to_ocsf`.  Only non-empty values are included in the
returned dicts so that ``to_ocsf`` falls back to its own defaults cleanly.
"""
from __future__ import annotations

import csv
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_CSV_TO_DTO: dict[str, str] = {
    "Access method":    "accessMethod",
    "Account ID":       "accountId",
    "Account name":     "accountName",
    "Action":           "actionType",
    "Application code": "applicationCode",
    "Audit code":       "auditCode",
    "Status":           "auditType",
    "Command":          "command",
    "Component":        "component",
    "Correlation ID":   "correlationId",
    "Identity type":    "identityType",
    "Description":      "message",
    "Safe":             "safe",
    "Service":          "serviceName",
    "Session ID":       "sessionId",
    "Event source":     "source",
    "Event target":     "target",
    "Target account":   "targetAccount",
    "Target platform":  "targetPlatform",
    "tenant_id":        "tenantId",
    "User ID":          "userId",
    "Username":         "username",
    "UUID":             "uuid",
    "Provider":         "cloudProvider",
}

_JSON_TO_DTO: dict[str, str] = {
    "Assets":               "cloudAssets",
    "Identities":           "cloudIdentities",
    "Roles":                "cloudRoles",
    "cloud_workspaces":     "cloudWorkspaces",
    "Workspaces and roles": "cloudWorkspacesAndRoles",
    "Custom data":          "customData",
    "Vaulted accounts":     "vaultedAccounts",
}

_EMPTY_JSON_VALUES = {"", "[]", "{}", "null"}


def _parse_json_field(raw: str) -> Any:
    raw = raw.strip()
    if raw in _EMPTY_JSON_VALUES:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def _iso_to_unix_ms(ts: str) -> int:
    """Convert an ISO 8601 timestamp string to Unix milliseconds."""
    if not ts:
        return 0
    try:
        ts_clean = ts.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_clean)
        return int(dt.timestamp() * 1000)
    except (ValueError, AttributeError):
        logger.warning("Could not parse timestamp: %r", ts)
        return 0


def load_events_from_csv(path: str | Path) -> list[dict[str, Any]]:
    """Read an Idira Audit report CSV and return a list of AuditDto-like dicts.

    Args:
        path: Path to the downloaded CSV report file.

    Returns:
        List of dicts in the same shape as AuditDto objects returned by the
        REST API, ready for :func:`transform.ocsf.to_ocsf`.
    """
    events: list[dict[str, Any]] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            dto: dict[str, Any] = {}

            for csv_col, dto_field in _CSV_TO_DTO.items():
                value = row.get(csv_col, "").strip()
                if value:
                    dto[dto_field] = value

            for csv_col, dto_field in _JSON_TO_DTO.items():
                parsed = _parse_json_field(row.get(csv_col, ""))
                if parsed is not None:
                    dto[dto_field] = parsed

            dto["timestamp"] = _iso_to_unix_ms(row.get("Timestamp", ""))
            events.append(dto)

    logger.info("Loaded %d events from CSV: %s", len(events), path)
    return events
