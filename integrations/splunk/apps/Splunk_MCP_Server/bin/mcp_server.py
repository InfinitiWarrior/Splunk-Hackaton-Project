"""
MCP REST Server Module.

This module implements the Splunk persistent REST endpoint for handling
MCP (Model Context Protocol) JSON-RPC requests. It provides the main
entry point for MCP communication within the Splunk environment.
"""

import os
import sys
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from splunk.persistconn.application import PersistentServerConnectionApplication

# Ensure the current directory is on sys.path for local imports
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from auth import MCPAuthorization
from constants import EVENT_RATE_LIMIT_REJECTED
from logging_config import (
    clear_log_context,
    get_logger,
    log_telemetry,
    update_log_context,
    update_log_context_req_id,
)
from mcp_message import MCPMessageHandler
from rate_limit_manager import RateLimitManager, RateLimits
from request_admission import RateLimitConfig, RequestAdmissionController
from settings import MCPSettings
from tool_manager import get_default_manager

# Module logger
logger = get_logger(__name__)
logger.info("Initializing MCP REST Handler")


class MCPRestHandler(PersistentServerConnectionApplication):
    """Persistent REST endpoint for MCP JSON-RPC."""

    MAX_REQUEST_BYTES = 262144

    def __init__(self, command_line: str, command_arg: str) -> None:
        """
        Initialize the MCP REST handler.

        Args:
            command_line: Command line arguments (required by Splunk).
            command_arg: Additional command arguments (required by Splunk).
        """
        super().__init__()

        # Keep tool manager persistent; avoid per-request reload.
        tool_manager = get_default_manager(reload=False)
        self.message_handler = MCPMessageHandler(tool_manager)
        self._admission = RequestAdmissionController(window_seconds=60)

    def handle(self, in_string: str) -> Dict[str, Any]:
        """
        Handle incoming HTTP requests for MCP protocol.

        This method processes all incoming MCP requests, parsing them through
        the message handler and returning properly formatted responses.

        Args:
            in_string: Raw HTTP request string containing JSON data.

        Returns:
            Dict containing HTTP response with status, headers, and payload.
        """

        # Generate a request ID for logging context
        update_log_context_req_id()

        admitted = False
        cfg: Optional[RateLimitConfig] = None
        resp_status = 500
        response: Dict[str, Any] = {}
        try:
            raw_len = (
                len(in_string)
                if isinstance(in_string, (bytes, bytearray))
                else len(in_string.encode("utf-8"))
            )
            logger.info("Request received, size=%d bytes", raw_len)

            if raw_len > self.MAX_REQUEST_BYTES:
                resp_status = 413
                response = self._build_response(
                    413,
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32600,
                            "message": "Request exceeds maximum allowed size",
                        },
                    },
                )
                return response

            # Parse the incoming request
            status_code, parsed_data = self.message_handler.parse_request(in_string)

            if status_code != 200:
                update_log_context(source_ip="unknown")
                logger.warning(
                    "Request parsing failed with status %d and %s",
                    status_code,
                    str(parsed_data),
                )
                resp_status = status_code
                response = self._build_response(status_code, parsed_data)
                return response

            # Extract the RPC request and auth token
            rpc_req = parsed_data["rpc_request"]
            auth_token = parsed_data["auth_token"]
            full_request = parsed_data["full_request"]

            source_ip = (full_request.get("connection") or {}).get("src_ip", "unknown")
            update_log_context(source_ip=source_ip)

            system_authtoken = (
                full_request.get("system_authtoken")
                or full_request.get("systemAuthtoken")
                or ((full_request.get("session") or {}).get("authtoken"))
            )
            # Phase 1: pre-check admission before token validation to protect
            # CPU/auth backend from over-quota or circuit-open traffic.
            pre_ok, limit_status, limit_message, cfg, rate_limits = self._admit_request(
                system_authtoken,
                source_ip=source_ip,
                is_authenticated=False,
                authenticated_identity=None,
                record=False,
            )
            if not pre_ok:
                log_telemetry(
                    EVENT_RATE_LIMIT_REJECTED, limit_status, error_message=limit_message
                )
                logger.warning(
                    "Request rejected by admission controls: %s", limit_message
                )
                resp_status = limit_status
                response = self._build_response(
                    limit_status,
                    {
                        "jsonrpc": "2.0",
                        "id": rpc_req.get("id", None),
                        "error": {
                            "code": -32010,
                            "message": limit_message,
                        },
                    },
                )
                return response

            validated_auth = self._validate_for_admission(
                rpc_req=rpc_req,
                auth_token=auth_token,
                system_authtoken=system_authtoken,
            )
            is_authenticated, authenticated_identity = self._admission_subject(
                validated_auth
            )
            if cfg is None:
                logger.warning("Admission config unavailable after pre-check")
                resp_status = 503
                response = self._build_response(
                    503,
                    {
                        "jsonrpc": "2.0",
                        "id": rpc_req.get("id", None),
                        "error": {
                            "code": -32010,
                            "message": "Rate limiting unavailable",
                        },
                    },
                )
                return response

            # Phase 2: record final admission against authenticated/unauthenticated
            # subject to enforce the intended tenant quotas.
            ok, limit_status, limit_message = self._admission.admit(
                source_ip=source_ip,
                config=cfg,
                is_authenticated=is_authenticated,
                authenticated_identity=authenticated_identity,
                record=True,
            )
            if not ok:
                log_telemetry(
                    EVENT_RATE_LIMIT_REJECTED, limit_status, error_message=limit_message
                )
                logger.warning(
                    "Request rejected by admission controls: %s", limit_message
                )
                resp_status = limit_status
                response = self._build_response(
                    limit_status,
                    {
                        "jsonrpc": "2.0",
                        "id": rpc_req.get("id", None),
                        "error": {
                            "code": -32010,
                            "message": limit_message,
                        },
                    },
                )
                return response

            admitted = True

            endpoint = parsed_data["full_request"]["restmap"]["conf"]["match"]

            try:
                source_ip = parsed_data["full_request"]["connection"]["src_ip"]
                update_log_context(source_ip=source_ip)
            except (KeyError, TypeError):
                pass

            # Handle the RPC method (timing & status logging handled by decorator)
            status_code, content = self.message_handler.handle_rpc_method(
                rpc_req,
                auth_token,
                system_authtoken,
                endpoint,
                validated_auth=validated_auth,
                rate_limits=rate_limits,
            )

            resp_status = status_code
            response = self._build_response(status_code, content, full_request)
            return response

        except Exception as e:
            update_log_context(source_ip="unknown")
            logger.exception("Unexpected error handling MCP request: %s", e)
            resp_status = 500
            response = self._build_response(
                500,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32603,
                        "message": "Internal server error",
                    },
                },
            )
            return response
        finally:
            if admitted and cfg is not None:
                self._admission.record_result(resp_status, cfg)
            logger.info("Response sent, status=%d", resp_status)
            clear_log_context()

    def _admit_request(
        self,
        system_authtoken: str,
        source_ip: str,
        is_authenticated: bool,
        authenticated_identity: Optional[str],
        record: bool = True,
    ) -> Tuple[bool, int, str, Optional[RateLimitConfig], Optional[RateLimits]]:
        """Apply rate-limit/circuit-breaker controls (fail closed)."""
        if not system_authtoken:
            return (
                False,
                503,
                "Rate limiting unavailable: missing system auth token",
                None,
                None,
            )

        try:
            rate_limits = RateLimitManager(system_authtoken).get_rate_limits()
            limits_data = rate_limits.data
            config = RateLimitConfig(
                # Keep admission controls independent from tools/call counters.
                # `global` is reserved for tool-call rate limiting.
                global_limit=int(limits_data.get("admission_global", 0)),
                tenant_authenticated_limit=int(
                    limits_data.get("tenant_authenticated", 240)
                ),
                tenant_unauthenticated_limit=int(
                    limits_data.get("tenant_unauthenticated", 60)
                ),
                circuit_breaker_failure_threshold=int(
                    limits_data.get("circuit_breaker_failure_threshold", 20)
                ),
                circuit_breaker_cooldown_seconds=int(
                    limits_data.get("circuit_breaker_cooldown_seconds", 30)
                ),
            )
        except Exception as exc:
            logger.warning("Failed to read rate limits configuration: %s", exc)
            return False, 503, "Rate limiting unavailable", None, None

        allowed, status, message = self._admission.admit(
            source_ip=source_ip,
            config=config,
            is_authenticated=is_authenticated,
            authenticated_identity=authenticated_identity,
            record=record,
        )
        return allowed, status, message, config, rate_limits

    def _validate_for_admission(
        self,
        rpc_req: Dict[str, Any],
        auth_token: str,
        system_authtoken: str,
    ) -> Optional[
        Tuple[bool, Optional[str], Optional[Dict[str, Any]], Optional[str], bool]
    ]:
        """Validate once up-front so admission can use authenticated quotas."""
        if rpc_req.get("method") == "ping" or not auth_token:
            return None
        try:
            return MCPAuthorization.validate_token(auth_token, system_authtoken)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Admission pre-validation failed: %s", exc)
            return None

    def _admission_subject(
        self,
        validated_auth: Optional[
            Tuple[bool, Optional[str], Optional[Dict[str, Any]], Optional[str], bool]
        ],
    ) -> Tuple[bool, Optional[str]]:
        if validated_auth is None:
            return False, None
        is_valid, normalized_token, user_info, _, _ = validated_auth
        if not is_valid:
            return False, None
        if isinstance(user_info, dict):
            username = user_info.get("username")
            if isinstance(username, str) and username.strip():
                return True, f"user:{username.strip()}"
        if isinstance(normalized_token, str) and normalized_token:
            return True, f"token:{normalized_token}"
        return True, None

    def handleStream(self, handle: Any, in_string: str) -> Optional[Any]:
        """
        Handle streaming requests (not implemented for MCP).

        Args:
            handle: Stream handle (unused).
            in_string: Input string (unused).

        Returns:
            None as streaming is not supported.
        """
        logger.warning("Stream handling requested but not supported")
        return None

    def done(self) -> None:
        """
        Cleanup method called when the handler completes handling a request.
        """
        pass

    _PRM_WELL_KNOWN_ENDPOINT = "/.well-known/oauth-protected-resource"

    @staticmethod
    def _prm_path(base_url: str) -> str:
        """Return the PRM discovery path appropriate for *base_url*.

        Splunkd routes custom REST endpoints under ``/services/`` on its
        management port (default 8089), so the prefix is required there.
        On other ports (e.g. Splunk Web on 443 behind a reverse proxy)
        the path must be reached via splunkweb's ``__raw`` proxy so that
        the PRM document is fetchable rather than returning HTML.
        """
        url_port = str(urlsplit(base_url).port or "")
        splunkd_url = MCPSettings.get().splunkd_url or ""
        mgmt_port = str(urlsplit(splunkd_url).port or "8089")
        if url_port == mgmt_port:
            return f"/services{MCPRestHandler._PRM_WELL_KNOWN_ENDPOINT}"
        return f"/en-US/splunkd/__raw/services{MCPRestHandler._PRM_WELL_KNOWN_ENDPOINT}"

    def _build_response(
        self, status: int, payload_obj: Any, full_request: Optional[dict] = None
    ) -> Dict[str, Any]:
        """
        Build a properly formatted HTTP response for Splunk.

        Args:
            status: HTTP status code.
            payload_obj: Response payload object (will be JSON-encoded by Splunk).
            full_request: Parsed request dict; used on 401 to extract the Host
                header and connection.listening_port for the WWW-Authenticate
                resource_metadata URL.

        Returns:
            Dict containing complete HTTP response structure.
        """
        headers = {"Content-Type": "application/json"}
        if status == 401:
            req_headers = (full_request or {}).get("headers") or []
            host = next(v for k, v in req_headers if str(k).lower() == "host")
            base_url = f"https://{host}".rstrip("/")
            prm_path = self._prm_path(base_url)
            headers["WWW-Authenticate"] = (
                f'Bearer resource_metadata="{base_url}{prm_path}"'
            )
        return {
            "status": status,
            "headers": headers,
            "payload": payload_obj,  # Splunk will JSON encode dict automatically
        }
