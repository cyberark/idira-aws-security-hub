"""Idira Audit SIEM API client.

Wraps the two-step stream API:
  POST /api/audits/stream/createQuery  -> cursorRef
  POST /api/audits/stream/results      -> { data: [AuditDto], paging: { cursor: { cursorRef } } }
"""
from __future__ import annotations

import base64
import datetime
import logging
import time
from typing import Iterator, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_RETRY_STATUS_CODES = frozenset([429, 500, 502, 503, 504])
_OAUTH2_SCOPE = "isp.audit.events:read"
_TOKEN_CACHE_BUFFER_SECONDS = 60

_TELEMETRY_INTEGRATION_NAME = "AWS Security Hub"
_TELEMETRY_INTEGRATION_TYPE = "SIEM"
_TELEMETRY_INTEGRATION_VERSION = "1.0"
_TELEMETRY_VENDOR_NAME = "AWS"


class AuditClient:
    """Thread-safe client for the Idira Audit SIEM stream API."""

    def __init__(
        self,
        base_url: str,
        identity_url: str,
        client_id: str,
        client_secret: str,
        web_app: str,
        api_key: str,
        timeout: int = 30,
        page_size: int = 500,
        max_events: int = 1000,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._identity_url = identity_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._web_app = web_app
        self._api_key = api_key
        self._timeout = timeout
        self._page_size = min(page_size, 500)
        self._max_events = max_events
        self._session = self._build_session()
        self._access_token: str | None = None
        self._token_valid_until: float = 0.0
        self._telemetry_header = self._build_telemetry_header()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=2,
            status_forcelist=_RETRY_STATUS_CODES,
            allowed_methods=["POST"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        return session

    @staticmethod
    def _build_telemetry_header() -> str:
        telemetry = (
            f"in={_TELEMETRY_INTEGRATION_NAME}&"
            f"it={_TELEMETRY_INTEGRATION_TYPE}&"
            f"iv={_TELEMETRY_INTEGRATION_VERSION}&"
            f"vn={_TELEMETRY_VENDOR_NAME}&"
        )
        return base64.b64encode(telemetry.encode()).decode()

    def _get_access_token(self) -> str:
        """Return a valid OAuth2 access token, refreshing if expired."""
        current_time = time.time()
        if self._access_token and current_time < self._token_valid_until:
            logger.debug("OAuth2 token cache hit")
            return self._access_token

        logger.debug("Requesting new OAuth2 token from %s", self._identity_url)
        resp = self._session.post(
            f'{self._identity_url}/oauth2/token/{self._web_app}',
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "scope": _OAUTH2_SCOPE,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        token_data = resp.json()
        self._access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 6 * 60 * 60)
        self._token_valid_until = current_time + expires_in - _TOKEN_CACHE_BUFFER_SECONDS
        logger.debug("OAuth2 token obtained; expires_in=%ss", expires_in)
        return self._access_token

    def _auth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_access_token()}",
            "x-api-key": self._api_key,
            "x-cybr-telemetry": self._telemetry_header,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _create_stream_query(
        self,
        date_from: str,
        date_to: str,
        app_codes: list[str] | None = None,
    ) -> str:
        """Create a stream query and return the initial cursorRef.

        Args:
            date_from: Start datetime string, format ``YYYY-MM-DD HH:MM:SS``. If None, defaults to now.
            date_to:   End datetime string,   format ``YYYY-MM-DD HH:MM:SS``.
            filter_model: Optional extra filter fields to merge into the request.

        Returns:
            cursorRef string to pass to `get_stream_results`.
        """
        base_filter: dict = {
            "date": {
                "dateFrom": date_from or datetime.datetime.now().isoformat()
            },
            "cloudProvider": [{
                  "op": "include",
                  "params": [
                    "AWS"
                  ],
            }]
        }
        if date_to:
            base_filter["date"]["dateTo"] = date_to
        if app_codes:
            base_filter.update({"applicationCode": [{
                "op": "include",
                "params": app_codes
            }]})

        payload = {
            "query": {
                "pageSize": self._page_size,
                "filterModel": base_filter,
            }
        }
        logger.debug("createQuery request: dateFrom=%s dateTo=%s", date_from, date_to)
        resp = self._session.post(
            f"{self._base_url}/api/audits/stream/createQuery",
            json=payload,
            headers=self._auth_headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        cursor_ref: str = resp.json()["cursorRef"]
        logger.debug("createQuery returned cursorRef=%s", cursor_ref)
        return cursor_ref

    def _get_stream_results(self, cursor_ref: str) -> (list[dict[str, Any]], str):
        """Fetch one page of results for the given cursorRef.

        Returns:
            Raw API response dict with keys ``data`` (list of AuditDto) and
            ``paging`` (containing next ``cursorRef``).
        """
        resp = self._session.post(
            f"{self._base_url}/api/audits/stream/results",
            json={"cursorRef": cursor_ref},
            headers=self._auth_headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        results_content = resp.json()
        return results_content["data"], results_content["paging"]["cursor"]["cursorRef"]

    def fetch_events_with_pagination(self,
                                     cursor_ref: str | None = None,
                                     date_from: str | None = None,
                                     date_to: str | None = None,
                                     app_codes: list[str] | None = None) -> (list[dict[str, Any]], str):
        """Fetch events with pagination support.

        Fetches pages until the limit is reached or no more pages exist.
        If cursor_ref is provided, it will be used to fetch pages. Otherwise, a new query will be created from the provided date range.
        """
        events: list[dict[str, Any]] = []
        page_count = 0
        next_cursor: str | None = None
        logger.info(f"[Pagination Loop] Start. Goal: {self._page_size}. Time: {date_from} -> {date_to or 'Now'}")

        # Step 1: Use existing cursor_ref or create an initial query
        if not cursor_ref:
            cursor_ref  = self._create_stream_query(date_from=date_from, date_to=date_to, app_codes=app_codes)

        # Step 2: Fetch pages
        while len(events) < self._max_events and cursor_ref:
            page_count += 1
            page_events, next_cursor = self._get_stream_results(cursor_ref=cursor_ref)

            if not page_events:
                logger.info(f"[Pagination Loop] Page {page_count}: Empty. Stopping.")
                break

            events.extend(page_events)
            logger.info(f"[Pagination Loop] Page {page_count}: +{len(page_events)} events. Total accumulated: {len(events)}")

            cursor_ref = next_cursor

            if not cursor_ref:
                logger.info("[Pagination Loop] No next cursor. Stopping.")
                break

            # Safety break to prevent infinite loops
            if len(events) >= self._max_events:
                logger.info(f"[Pagination Loop] Threshold reached ({len(events)} >= {self._max_events}). Stopping fetch.")
                break

        logger.info(f"[Pagination Result] Returning {len(events)} events")
        return events, next_cursor