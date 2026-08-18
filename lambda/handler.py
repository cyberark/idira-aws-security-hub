"""Lambda entrypoint for the Idira Audit → AWS Security Hub ETL.

All credential and configuration resolution is handled by :mod:`config`.
See that module's docstring for the full list of environment variables.

Flow:
  1. Resolve Idira base URL and OAuth2 credentials via config (SSM/Secrets Manager or .env).
  2. Load the last-run timestamp cursor (SSM in AWS, local file when LOCAL_EXECUTION=true).
  3. Optionally filter by APPLICATION_CODES (comma-separated env var).
  4. Create a stream query via POST /api/audits/stream/createQuery.
  5. Paginate results via POST /api/audits/stream/results.
  6. For each AuditDto: transform to OCSF Detection Finding.
  7. Batch-import OCSF findings to Security Hub via BatchImportFindingsV2.
  8. Persist the current run's end timestamp as the next cursor.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

import config
from idira.client import AuditClient
from transform.ocsf import to_ocsf
from aws.security_hub import SecurityHubPublisher

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler function."""
    audit_config = config.get_idira_audit_config()
    aws_account_id = config.get_aws_account_id()
    aws_region = config.get_aws_region()
    app_codes = config.get_application_codes()

    cursor = config.load_cursor()
    days = config.get_fetch_events_days()
    if days > 0:
        date_from = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    else:
        date_from = datetime.now(timezone.utc).isoformat()

    audit_client = AuditClient(
        base_url=audit_config["api_base_url"],
        identity_url=audit_config["identity_url"],
        client_id=audit_config["client_id"],
        client_secret=audit_config["client_secret"],
        web_app=audit_config["web_app"],
        api_key=audit_config["api_key"],
    )
    publisher = SecurityHubPublisher(region=aws_region)

    total_imported = 0
    total_failed = 0
    transform_errors = 0

    logger.info(f"Fetching Idira audit events for app_codes {app_codes or 'all'}")

    events, next_cursor = audit_client.fetch_events_with_pagination(cursor_ref=cursor,
                                                                    date_from=date_from,
                                                                    app_codes=app_codes)

    ocsf_findings = []
    for audit_event in events:
        try:
            ocsf_finding = to_ocsf(
                audit_event,
                aws_account_id=aws_account_id,
                aws_region=aws_region,
            )
            ocsf_findings.append(ocsf_finding)
        except Exception as exc:
            transform_errors += 1
            logger.error(
                "Transform error",
                extra={"uuid": audit_event.get("uuid"), "error": str(exc)},
            )

    if ocsf_findings:
        total_imported, total_failed = publisher.batch_import(ocsf_findings)

    config.save_cursor(next_cursor)

    summary = {
        "date_from": date_from,
        "app_codes_filter": app_codes,
        "findings_imported": total_imported,
        "findings_failed": total_failed,
        "transform_errors": transform_errors,
    }
    logger.info("Run complete: %s", summary)
    return summary
