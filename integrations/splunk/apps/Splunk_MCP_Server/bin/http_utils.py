import json
from typing import Any, Collection, Dict, Optional, Union


def extract_rest_uri(request: Dict[str, Any]) -> Optional[str]:
    """Extract server.rest_uri from a Splunk persistent-connection request dict.

    Returns the trimmed URI string (e.g. "https://127.0.0.1:8089"),
    or None if not present.
    """
    server = request.get("server")
    if isinstance(server, dict):
        rest_uri = server.get("rest_uri")
        if rest_uri:
            return str(rest_uri).strip()
    return None


class Request:
    """Represents an HTTP request with helper functions."""

    def __init__(self, in_string: str):
        try:
            data = json.loads(in_string)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON input: {e}")

        if "method" not in data:
            raise ValueError("Missing 'method' field in request data")

        self.method = data.get("method", "").upper()
        self.raw_payload = data.get("payload")
        self.session_key = self._extract_session_key(data)

    def _extract_session_key(self, data: Optional[Dict[str, Any]]) -> Optional[str]:
        if data is None or not isinstance(data, dict):
            return None
        return (
            data.get("system_authtoken")
            or data.get("systemAuthtoken")
            or ((data.get("session") or {}).get("authtoken"))
        )

    def json(self) -> Dict[str, Any]:
        return json.loads(self.raw_payload)


class Response:
    """Represents an HTTP response with helper functions."""

    def __init__(self, status):
        self._status: int = status
        self._headers: Dict[str, str] = {}
        self._payload: Dict[str, Any] = {}

    @staticmethod
    def ok() -> "Response":
        return Response(status=200)

    @staticmethod
    def bad_request(details: Optional[Union[str, Dict[str, Any]]]) -> "Response":
        payload: Dict[str, Any] = {
            "error": True,
            "code": "invalid_request",
        }
        if details is not None:
            payload["details"] = details
        return Response(status=400).json(payload)

    @staticmethod
    def method_not_allowed(method: str, allowed_methods: Collection[str]) -> "Response":
        payload = {
            "error": True,
            "code": "method_not_allowed",
            "message": f"Method {method} is not allowed",
            "allowed_methods": sorted(allowed_methods),
        }
        return Response(status=405).json(payload)

    @staticmethod
    def internal_server_error(details: str) -> "Response":
        payload = {
            "error": True,
            "code": "internal_server_error",
            "details": details,
        }

        return Response(status=500).json(payload)

    @staticmethod
    def unauthorized() -> "Response":
        payload = {
            "error": True,
            "code": "missing_auth",
            "message": "A valid session or system auth token is required.",
        }
        return Response(status=401).json(payload)

    def json(self, payload: Dict[str, Any]) -> "Response":
        self._headers["Content-Type"] = "application/json"
        self._payload = payload
        return self

    def build(self):
        return {
            "status": self._status,
            "headers": self._headers,
            "payload": self._payload,
        }
