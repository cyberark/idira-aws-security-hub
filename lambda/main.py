"""Local entry point for manually fetching Idira audit events.

Requires LOCAL_EXECUTION=true and the following env vars (or .env file):
  IDIRA_BASE_URL, IDIRA_TOKEN_URL, IDIRA_CLIENT_ID,
  IDIRA_CLIENT_SECRET, IDIRA_API_KEY, LOOKBACK_HOURS
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta

import config
from idira.client import AuditClient
from idira.csv_reader import load_events_from_csv
from transform.ocsf import to_ocsf
from aws.security_hub import SecurityHubPublisher

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def main() -> None:
    event_source = config.get_event_source()
    aws_region = config.get_aws_region()
    aws_account_id = config.get_aws_account_id()

    if event_source == "csv":
        csv_path = config.get_csv_report_path()
        logger.info(f"Loading events from CSV: {csv_path}")
        events = load_events_from_csv(csv_path)
        logger.info(f"Done. Total events loaded from CSV: {len(events)}")
    else:
        audit_config = config.get_idira_audit_config()
        from_date = (datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        logger.info(f"Fetching events from: {from_date}")

        client = AuditClient(
            base_url=audit_config["api_base_url"],
            identity_url=audit_config["identity_url"],
            client_id=audit_config["client_id"],
            client_secret=audit_config["client_secret"],
            web_app=audit_config["web_app"],
            api_key=audit_config["api_key"],
        )
        app_codes = config.get_application_codes()
        events, next_cursor = client.fetch_events_with_pagination(cursor_ref=None, date_from=from_date, app_codes=app_codes)
        if events:
            with open('events.json', 'w') as fp:
                json.dump(events, fp, indent=2)
        logger.info(f"Done. Total events fetched: {len(events)}")

    ocsf_findings = [
        to_ocsf(event, aws_account_id=aws_account_id, aws_region=aws_region)
        for event in events
    ]
    if ocsf_findings:
        with open('ocsf_findings_v2.json', 'w') as fp:
            json.dump(ocsf_findings, fp, indent=2)
    logger.info(f"Done. Total OCSF findings: {len(ocsf_findings)}")

    aws_profile = config.get_aws_profile()
    publisher = SecurityHubPublisher(aws_region, profile_name=aws_profile)
    success, failed = publisher.batch_import(ocsf_findings)
    logger.info("Security Hub BatchImportFindingsV2 complete: success=%d failed=%d", success, failed)

if __name__ == "__main__":
    main()
