"""Configuration resolution for AWS Lambda and local development.

Idira Audit API base URL     <- IDIRA_BASE_API_URL
OAuth2 token URL             <- IDIRA_TOKEN_URL
OAuth2 client ID             <- IDIRA_CLIENT_ID
OAuth2 secret                <- IDIRA_CLIENT_SECRET
OAuth2 web app               <- IDIRA_WEB_APP
API key                      <- IDIRA_API_KEY
Run cursor                   <- local file at            LOCAL_CURSOR_FILE (default: .idira_cursor)

AWS (only):
  OAuth2 credentials <- Secrets Manager      (IDIRA_SECRET_ARN)

Common env vars (both modes):
  AWS_ACCOUNT_ID     12-digit AWS account ID
  AWS_REGION         AWS region (default: us-east-1)
  APPLICATION_CODES  Optional comma-separated Idira application codes to filter
                     (e.g. "PAM,EPM,IDENTITY"). Leave unset to fetch all services.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"

def _load_dotenv() -> None:
    """Load a .env file sitting next to this module.

    Always called at import time so that LOCAL_EXECUTION (and all other vars)
    can live exclusively in .env without needing to be pre-set in the shell.
    Silently skips if python-dotenv is not installed (not needed in Lambda runtime).
    """
    try:
        from dotenv import load_dotenv  # type: ignore[import-untyped]
    except ImportError:
        return

    env_path = Path(__file__).parent / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)
        logger.debug("Loaded .env from %s", env_path)


_load_dotenv()

IS_LOCAL: bool = os.environ.get("LOCAL_EXECUTION", "").lower() in ("true", "1", "yes")


def get_idira_audit_config() -> dict[str, str]:
    """Resolve OAuth2 credentials and API key for the Idira Audit API.

    Returns a dict with keys: ``token_url``, ``client_id``, ``client_secret``, ``api_key``.
    """
    if IS_LOCAL:
        return {
            "api_base_url": os.environ.get("IDIRA_API_BASE_URL").rstrip("/"),
            "identity_url": os.environ.get("IDIRA_IDENTITY_URL").rstrip("/"),
            "client_id": os.environ.get("IDIRA_CLIENT_ID"),
            "client_secret": os.environ.get("IDIRA_CLIENT_SECRET"),
            "web_app": os.environ.get("IDIRA_WEB_APP"),
            "api_key": os.environ.get("IDIRA_API_KEY"),
        }

    import boto3
    secret_arn = os.environ.get("IDIRA_SECRET_ARN")
    try:
        resp = boto3.client("secretsmanager").get_secret_value(SecretId=secret_arn)
        secret = json.loads(resp["SecretString"])
        return {
            "api_base_url": secret.get("api_base_url"),
            "identity_url": secret.get("identity_url"),
            "client_id": secret.get("client_id"),
            "client_secret": secret.get("client_secret"),
            "web_app": secret.get("web_app"),
            "api_key": secret.get("api_key"),
        }
    except Exception as exc:
        raise RuntimeError(f"Failed to read secret '{secret_arn}': {exc}") from exc


def get_application_codes() -> Optional[list[str]]:
    """Return a list of Idira application codes to filter, or None for all services.

    Reads APPLICATION_CODES env var (comma-separated).  Examples::

        APPLICATION_CODES=PAM           -> ["PAM"]
        APPLICATION_CODES=PAM,EPM       -> ["PAM", "EPM"]
        APPLICATION_CODES=              -> None  (fetch all)
    """
    raw = os.environ.get("APPLICATION_CODES", "").strip()
    if not raw:
        return None
    codes = [c.strip() for c in raw.split(",") if c.strip()]
    return codes or None


def get_event_source() -> str:
    """Return the event source mode: ``'api'`` (default) or ``'csv'``.

    Controlled by the ``EVENT_SOURCE`` env var.
    """
    return os.environ.get("EVENT_SOURCE", "api").lower().strip()


def get_csv_report_path() -> str:
    """Return the path to a downloaded Idira Audit CSV report.

    Controlled by the ``CSV_REPORT_PATH`` env var.
    """
    return os.environ.get("CSV_REPORT_PATH", "c3_events_report.csv")


def get_aws_account_id() -> str:
    return os.environ.get("AWS_ACCOUNT_ID")


def get_aws_region() -> str:
    return os.environ.get("AWS_REGION", "us-east-1")


def get_aws_profile() -> (str, str):
    if IS_LOCAL:
        return os.environ.get("AWS_PROFILE") or None
    return None

def get_fetch_events_days() -> int:
    return int(os.environ.get("FETCH_EVENTS_DAYS", "0"))


def load_cursor() -> str:
    import boto3
    param_name = os.environ.get("CURSOR_SSM_PARAM")
    ssm = boto3.client("ssm")
    try:
        resp = ssm.get_parameter(Name=param_name)
        value = resp["Parameter"]["Value"]
        if value == "UNSET":
            logger.info("SSM cursor is unset (first run)")
            return ""
        logger.info("Loaded SSM cursor: %s", value)
        return value
    except ssm.exceptions.ParameterNotFound:
        logger.info("No SSM cursor found")
        return ""


def save_cursor(cursor: str) -> None:

    import boto3
    param_name = os.environ.get("CURSOR_SSM_PARAM")
    boto3.client("ssm").put_parameter(
        Name=param_name, Value=cursor, Type="String", Overwrite=True
    )
    logger.info(f"Saved SSM cursor: {cursor}")
