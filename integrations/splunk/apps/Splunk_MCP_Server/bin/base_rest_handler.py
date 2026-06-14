"""
Base REST Handler Module.

Provides a reusable base class for Splunk persistent REST handlers that
need authenticated access to splunkd.  Handlers choose an ``AuthMode``
to control which tokens are extracted from each incoming request and
which ``splunklib.client.Service`` instances are created.

Typical subclass patterns::

    # System-only (e.g. public metadata endpoints):
    class MyHandler(BaseRestHandler, PersistentServerConnectionApplication):
        AUTH_MODE = AuthMode.SYSTEM

    # Dual-token (e.g. MCP protocol endpoint):
    class MCPHandler(BaseRestHandler, PersistentServerConnectionApplication):
        AUTH_MODE = AuthMode.SYSTEM_AND_USER
"""

import json
import os
import sys
from collections.abc import Mapping
from enum import Enum
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

# Add the directory where this script resides to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunklib.client as client
from constants import AUTHORIZATION_HEADER_NAME, AUTHTOKEN, SESSION, SYSTEM_AUTHTOKEN
from http_utils import extract_rest_uri
from logging_config import get_logger

logger = get_logger(__name__)


class AuthMode(str, Enum):
    """How the handler should authenticate back to splunkd.

    SYSTEM:
        Uses only the system auth token (``passSystemAuth = true``).
        Creates ``self.system_service``.

    USER:
        Uses only the user session token
        (``requireAuthentication = true`` and ``passSession = true``).
        Creates ``self.service``.

    SYSTEM_AND_USER:
        Extracts the system token immediately (always available) and the
        user token when present.  Creates ``self.system_service`` on
        every request and ``self.service`` once the user token is
        validated.  Requires ``passSystemAuth = true`` in
        ``restmap.conf``.
    """

    SYSTEM = "system"
    USER = "user"
    SYSTEM_AND_USER = "system_and_user"


_USER_AUTH_KWARGS: Tuple[str, ...] = ("token", "splunkToken")


class BaseRestHandler(object):
    AUTH_MODE: AuthMode = AuthMode.SYSTEM

    # Namespace used by the SDK when resolving objects/configs.
    SPLUNK_OWNER: str = "nobody"
    SPLUNK_APP: Optional[str] = None
    SPLUNK_SHARING: Optional[str] = None

    def __init__(self):
        # Per-request SDK services.  We rebuild on every request because
        # auth tokens come from the incoming request and persistent
        # handlers can live across multiple requests.
        self.service: Optional[client.Service] = None
        self.system_service: Optional[client.Service] = None

    @staticmethod
    def parse_request(in_string: str) -> Dict[str, Any]:
        """Parse the JSON request sent by Splunk's persistent connection framework."""
        if not in_string:
            raise ValueError("Request body is empty.")

        try:
            request = json.loads(in_string)
        except json.JSONDecodeError as exc:
            raise ValueError("Request body is not valid JSON.") from exc

        if not isinstance(request, dict):
            raise ValueError("Request JSON must be an object.")

        logger.info("Request parsed successfully")
        return request

    # ------------------------------------------------------------------
    # Service initialization
    # ------------------------------------------------------------------

    def initialize_system_service(self, request: Mapping[str, Any]) -> client.Service:
        """Create a Splunk SDK Service backed by the **system** auth token.

        The system token is injected by Splunk when
        ``passSystemAuth = true`` in ``restmap.conf``.  The resulting
        service is stored as ``self.system_service``.

        For ``AuthMode.SYSTEM`` handlers this is the only service
        needed; for ``AuthMode.SYSTEM_AND_USER`` handlers it provides
        infrastructure-level access (config reads, KV Store, rate
        limits) while user-scoped work goes through ``self.service``.

        Returns:
            The newly created :class:`splunklib.client.Service`.

        Raises:
            ValueError: If the system auth token is not present in the
                request (i.e. ``passSystemAuth`` is not enabled).
        """
        token = self._extract_system_token(request)
        self.system_service = self._build_service({"token": token}, request)

        scheme, host, port = self._parse_rest_uri(request)
        logger.info("Initialized system service for %s://%s:%s", scheme, host, port)

        return self.system_service

    def initialize_user_service(
        self,
        auth_kwargs: Mapping[str, str],
        request: Mapping[str, Any],
    ) -> client.Service:
        """Create a Splunk SDK Service backed by a **user** credential.

        The caller supplies *auth_kwargs* — the splunklib ``Service`` auth
        kwargs chosen at the point where the credential's presentation is
        known:

        * ``{"token": <value>}``        → ``Authorization: Splunk …``
          (classic session keys / Splunk-scheme Authorization tokens).
        * ``{"splunkToken": <value>}``  → ``Authorization: Bearer …``
          (OAuth/JWT access tokens).

        The resulting service is stored as ``self.service``.

        Raises:
            ValueError: If *auth_kwargs* is empty or its value is empty.
        """
        if len(auth_kwargs) != 1:
            raise ValueError(
                "User auth kwargs must be a single-entry mapping: "
                "{'token': ...} or {'splunkToken': ...}."
            )
        kwarg, value = next(iter(auth_kwargs.items()))
        if kwarg not in _USER_AUTH_KWARGS or not (value or "").strip():
            raise ValueError(
                f"User auth kwargs must use one of {_USER_AUTH_KWARGS} "
                "with a non-empty value."
            )

        self.service = self._build_service(auth_kwargs, request)

        scheme, host, port = self._parse_rest_uri(request)
        logger.info(
            "Initialized user service (auth=%s) for %s://%s:%s",
            kwarg,
            scheme,
            host,
            port,
        )

        return self.service

    # ------------------------------------------------------------------
    # Backward-compatible convenience
    # ------------------------------------------------------------------

    def initialize_service(self, request: Mapping[str, Any]) -> client.Service:
        """Create a Splunk SDK Service using the handler's AUTH_MODE.

        This is the legacy entry-point kept for backward compatibility.

        * ``AuthMode.SYSTEM`` — equivalent to
          :meth:`initialize_system_service`.  The service is stored
          as **both** ``self.system_service`` and ``self.service`` so
          that existing callers that reference ``self.service`` continue
          to work.
        * ``AuthMode.USER`` — extracts the session token and calls
          :meth:`initialize_user_service`.
        * ``AuthMode.SYSTEM_AND_USER`` — raises; callers should use the
          split methods directly.
        """
        if self.AUTH_MODE == AuthMode.SYSTEM_AND_USER:
            raise RuntimeError(
                "SYSTEM_AND_USER handlers must call "
                "initialize_system_service() and "
                "initialize_user_service() separately."
            )

        if self.AUTH_MODE == AuthMode.SYSTEM:
            service = self.initialize_system_service(request)
            # Keep self.service pointing at the system service so that
            # existing SYSTEM-mode callers that reference self.service
            # still work.
            self.service = service
            return service

        # AuthMode.USER
        token = self._extract_user_session_token(request)
        return self.initialize_user_service({"token": token}, request)

    # ------------------------------------------------------------------
    # Token extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_system_token(request: Mapping[str, Any]) -> str:
        """Extract the system auth token from the request.

        Raises:
            ValueError: If the token is missing
                (``passSystemAuth = false`` in ``restmap.conf``).
        """
        token = request.get(SYSTEM_AUTHTOKEN)
        if token:
            logger.info("Extracted system auth token")
            return str(token)

        raise ValueError(
            "Missing system auth token in request. "
            "Set passSystemAuth = true in restmap.conf."
        )

    @staticmethod
    def _extract_user_session_token(request: Mapping[str, Any]) -> str:
        """Extract the user session token from the request.

        Raises:
            ValueError: If the token is missing
                (``requireAuthentication`` or ``passSession`` not set).
        """
        session = request.get(SESSION, {})
        if isinstance(session, Mapping):
            token = session.get(AUTHTOKEN)
            if token:
                logger.info("Extracted user session token")
                return str(token)

        raise ValueError(
            "Missing user session token in request. "
            "Use requireAuthentication = true and passSession = true "
            "in restmap.conf."
        )

    @staticmethod
    def extract_bearer_token_and_scheme(
        request: Mapping[str, Any],
    ) -> Optional[Tuple[str, str]]:
        """Extract token and HTTP scheme from the ``Authorization`` header.

        Supports headers delivered as a list of pairs (Splunk's persistent
        connection format) or as a plain dict.

        Returns:
            ``(token, scheme)`` where *scheme* is ``\"bearer\"`` or ``\"splunk\"``
            (lowercase), or ``None`` if the header is absent, malformed, or
            uses an unrecognized scheme.
        """
        headers = request.get("headers", [])
        auth_header = ""
        if isinstance(headers, dict):
            auth_header = headers.get("Authorization") or headers.get(
                AUTHORIZATION_HEADER_NAME, ""
            )
        elif isinstance(headers, list):
            for pair in headers:
                if (
                    isinstance(pair, list)
                    and len(pair) >= 2
                    and str(pair[0]).lower() == AUTHORIZATION_HEADER_NAME
                ):
                    auth_header = str(pair[1])
                    break

        if not isinstance(auth_header, str) or not auth_header:
            return None

        scheme, _, token = auth_header.partition(" ")
        scheme = scheme.lower()
        if scheme in ("bearer", "splunk") and token.strip():
            return token.strip(), scheme
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_service(
        self,
        auth_kwargs: Mapping[str, str],
        request: Mapping[str, Any],
    ) -> client.Service:
        """Build a :class:`splunklib.client.Service` from splunklib auth kwargs.

        *auth_kwargs* must be ``{"token": ...}`` or ``{"splunkToken": ...}``.
        """
        scheme, host, port = self._parse_rest_uri(request)

        service_kwargs: Dict[str, Any] = {
            "scheme": scheme,
            "host": host,
            "port": port,
            **auth_kwargs,
            "owner": self.SPLUNK_OWNER,
        }

        if self.SPLUNK_APP is not None:
            service_kwargs["app"] = self.SPLUNK_APP

        if self.SPLUNK_SHARING is not None:
            service_kwargs["sharing"] = self.SPLUNK_SHARING

        return client.Service(**service_kwargs)

    @staticmethod
    def _parse_rest_uri(request: Mapping[str, Any]) -> Tuple[str, str, int]:
        """
        Parse request['server']['rest_uri'] into (scheme, host, port).

        Example:
            https://127.0.0.1:8089 -> ("https", "127.0.0.1", 8089)
        """
        rest_uri = extract_rest_uri(request)
        if not rest_uri:
            raise ValueError("Request is missing server.rest_uri.")

        parsed = urlparse(rest_uri)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError(f"Invalid server.rest_uri: {rest_uri}")

        return parsed.scheme, parsed.hostname, parsed.port or 8089
