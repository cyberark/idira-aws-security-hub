"""AWS Security Hub publisher using BatchImportFindingsV2.

Features:
  - Automatic chunking (max 100 findings per call)
  - JSON-string encoding of each finding as required by the API
  - Structured error logging per failed finding
  - Aggregated success/failure counters

Strategy:
  Attempts the standard boto3 client method first. If the runtime's botocore
  doesn't include BatchImportFindingsV2 yet, falls back to a direct SigV4-signed
  HTTP call. Once the API is GA in the Lambda runtime SDK, remove the
  _DirectHttpTransport class and the fallback logic.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from itertools import islice
from typing import Any, Iterator

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

logger = logging.getLogger(__name__)

_BATCH_SIZE = 100


def _chunked(iterable: list[Any], size: int) -> Iterator[list[Any]]:
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


class _Transport(ABC):
    @abstractmethod
    def send(self, findings: list[str]) -> dict[str, Any]: ...


class _Boto3Transport(_Transport):
    """Standard boto3 client call — preferred when available."""

    def __init__(self, client) -> None:
        self._client = client

    def send(self, findings: list[str]) -> dict[str, Any]:
        return self._client.batch_import_findings_v2(Findings=findings)


# TODO: Remove this class once BatchImportFindingsV2 is GA in the Lambda runtime SDK.
class _DirectHttpTransport(_Transport):
    """SigV4-signed direct HTTP call — workaround for preview SDK."""

    def __init__(self, credentials, region: str) -> None:
        self._credentials = credentials
        self._region = region
        self._url = f"https://securityhub.{region}.amazonaws.com/findingsv2/import"

    def send(self, findings: list[str]) -> dict[str, Any]:
        import urllib.request
        import urllib.error

        body = json.dumps({"Findings": findings})
        request = AWSRequest(method="POST", url=self._url, data=body, headers={
            "Content-Type": "application/json",
        })
        SigV4Auth(self._credentials, "securityhub", self._region).add_auth(request)

        req = urllib.request.Request(
            url=self._url,
            data=body.encode(),
            headers=dict(request.headers),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode() if exc.fp else ""
            logger.error("HTTP %d from findingsv2/import: %s", exc.code, error_body)
            raise


def _create_transport(session: boto3.Session, region: str) -> _Transport:
    """Select the best available transport for BatchImportFindingsV2."""
    client = session.client("securityhub", region_name=region)
    if hasattr(client, "batch_import_findings_v2"):
        logger.info("Using boto3 transport for BatchImportFindingsV2")
        return _Boto3Transport(client)
    logger.info("boto3 client lacks batch_import_findings_v2; using direct HTTP transport")
    credentials = session.get_credentials().get_frozen_credentials()
    return _DirectHttpTransport(credentials, region)


class SecurityHubPublisher:
    """Publishes OCSF findings to AWS Security Hub via BatchImportFindingsV2."""

    def __init__(self, region: str, profile_name: str | None = None) -> None:
        session = boto3.Session(profile_name=profile_name, region_name=region)
        self._transport = _create_transport(session, region)

    def batch_import(self, findings: list[dict[str, Any]]) -> tuple[int, int]:
        """Import OCSF findings via BatchImportFindingsV2 in batches of up to 100.

        Each finding dict is JSON-encoded to a string as required by the API's
        Findings array format.

        Returns:
            Tuple of (success_count, failure_count).
        """
        if not findings:
            return 0, 0

        total_success = 0
        total_failed = 0

        for chunk in _chunked(findings, _BATCH_SIZE):
            encoded_findings = [json.dumps(f) for f in chunk]
            try:
                resp = self._transport.send(encoded_findings)
                success = resp.get("SuccessCount", 0)
                failed = resp.get("FailedCount", 0)
                total_success += success
                total_failed += failed

                for failure in resp.get("FailedFindings", []):
                    logger.error(
                        "Finding rejected: id=%s code=%s message=%s",
                        failure.get("Id"),
                        failure.get("ErrorCode"),
                        failure.get("ErrorMessage"),
                    )

                logger.info("BatchImportFindingsV2: success=%d failed=%d", success, failed)

            except Exception as exc:
                logger.error(
                    "batch_import_findings_v2 error (batch_size=%d): %s",
                    len(chunk),
                    exc,
                )
                total_failed += len(chunk)

        return total_success, total_failed
