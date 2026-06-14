"""
Utility for interacting with Splunk KV Store collections.

Provides thin CRUD wrappers around Splunk's REST API so other modules can reuse
consistent request formatting, namespacing, and error handling.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional

from requests import Response
from settings import MCPSettings
from splunk_api import call_splunk_api

_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from logging_config import get_logger  # noqa: E402 (path bootstrap above)

logger = get_logger(__name__)


class KVStoreManager:
    """
    Helper class for performing common KV Store operations.

    Args:
        session_key: Splunk session/system key for auth.
        collection: KV Store collection name.
        app_name: Optional app namespace override (defaults to MCP app).
        owner: Splunk entity owner (defaults to nobody).
    """

    def __init__(
        self,
        session_key: str,
        collection: str,
        app_name: Optional[str] = None,
        owner: str = "nobody",
    ) -> None:
        self.session_key = session_key
        self.collection = collection
        settings = MCPSettings.get()
        self.app_name = app_name or settings.app_name
        self.owner = owner

    def insert(self, document: Dict[str, Any]):
        """Create a new KV document."""
        return self._request(
            method="POST",
            data=self._as_json(document),
            headers={"Content-Type": "application/json"},
        )

    def batch_save(self, documents: list[Dict[str, Any]]) -> Response | None:
        """
        Insert or update multiple documents in a single request.
        Returns None if the input list is empty, as the KV store API rejects such requests.
        """
        if not documents:
            return None
        return self._request(
            method="POST",
            suffix="/batch_save",
            data=self._as_json(documents),
            headers={"Content-Type": "application/json"},
        )

    def update(self, key: str, document: Dict[str, Any]) -> Response:
        """Partial update of an existing KV document."""
        return self._request(
            method="POST",
            suffix=f"/{key}",
            data=self._as_json(document),
            headers={"Content-Type": "application/json"},
        )

    def replace(self, key: str, document: Dict[str, Any]) -> Response:
        """Replace an existing document entirely."""
        return self._request(
            method="PUT",
            suffix=f"/{key}",
            data=self._as_json(document),
            headers={"Content-Type": "application/json"},
        )

    def delete(self, key: str) -> Response:
        """Delete a document by KV _key."""
        return self._request(method="DELETE", suffix=f"/{key}")

    def get(self, key: str) -> Response:
        """Retrieve a single document by key."""
        return self._request(method="GET", suffix=f"/{key}")

    def query(self, query: Optional[Dict[str, Any]] = None, **params: Any) -> Response:
        """
        Run a KV Store query.

        Args:
            query: Query filter dictionary (converted to JSON).
            params: Additional Splunk query string params (count, sort, etc.).
        """
        request_params = dict(params)
        if query is not None:
            request_params["query"] = self._as_json(query)
        return self._request(method="GET", params=request_params)

    def _request(
        self,
        method: str,
        suffix: str = "",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[str] = None,
    ) -> Response:
        api_endpoint = self._build_api_path(suffix)
        logger.info(
            "KV request: %s %s (collection=%s, owner=%s)",
            method,
            api_endpoint,
            self.collection,
            self.owner,
        )
        return call_splunk_api(
            session_key=self.session_key,
            method=method,
            api=api_endpoint,
            headers=headers,
            params=params,
            data=data,
        )

    def _build_api_path(self, suffix: str) -> str:
        suffix = suffix or ""
        return (
            f"servicesNS/{self.owner}/{self.app_name}/storage/collections/data/"
            f"{self.collection}{suffix}"
        )

    @staticmethod
    def _as_json(obj: Any) -> str:
        if isinstance(obj, str):
            return obj
        return json.dumps(obj, separators=(",", ":"))


__all__ = ["KVStoreManager"]
