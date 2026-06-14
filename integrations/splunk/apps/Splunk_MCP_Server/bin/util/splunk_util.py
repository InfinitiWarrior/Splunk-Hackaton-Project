"""Utility helpers for building Splunk REST handler responses."""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Mapping, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from constants import CONTENT_TYPE_JSON


class SplunkUtil:

    @staticmethod
    def create_json_response(
        status: int,
        payload: Any = None,
        error: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Build the response dictionary expected by Splunk persistent REST handlers.

        Rules:
        - Use `payload` for a normal JSON response body.
        - Use `error` for an error response body: {"error": "..."}.
        - Do not pass both `payload` and `error`.
        """
        if payload is not None and error is not None:
            raise ValueError("Provide either 'payload' or 'error', not both.")

        response_headers = {"Content-Type": CONTENT_TYPE_JSON}
        if headers:
            response_headers.update(dict(headers))

        response: Dict[str, Any] = {
            "status": status,
            "headers": response_headers,
        }

        if error is not None:
            response["payload"] = {"error": error}
        else:
            response["payload"] = {} if payload is None else payload

        return response
