"""
MCP Message Handler Module.

This module provides comprehensive handling of MCP (Model Context Protocol) JSON-RPC
messages, including request parsing, method dispatch, and response formatting.
The module ensures proper error handling and logging throughout the message lifecycle.
"""

from __future__ import annotations

import base64
import http
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from auth import MCPAuthorization
from constants import (
    AUTHORIZATION_HEADER_NAME,
    EVENT_AUTH_ACCESS_DENIED,
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_INVALID_AUDIENCE,
    EVENT_AUTH_SUCCESS,
    EVENT_AUTH_TOKEN_DECODE_ERROR,
    EVENT_INITIALIZE_COMPLETE,
    EVENT_NOTIFICATION_RECEIVED,
    EVENT_TOOL_CALL_COMPLETE,
    EVENT_TOOL_CALL_ERROR,
    EVENT_TOOL_RATE_LIMIT_EXCEEDED,
    EVENT_TOOLS_LIST_COMPLETE,
    TELEMETRY_SUPPRESS_KEY,
    TRACEPARENT_HEADER_NAME,
)
from logging_config import (
    get_logger,
    log_telemetry,
    update_log_context,
    update_log_context_traceparent,
)
from rate_limit_manager import RateLimitCounterExceeded, RateLimitManager, RateLimits
from settings import MCPSettings
from splunk_api import get_installed_apps
from tool_manager import ArgumentType, Tool, ToolArgument, ToolManager

# Type aliases for better code readability
JsonDict = Union[Dict[str, Any], None]
RpcId = Any

# Module logger
logger = get_logger(__name__)
MAX_PAYLOAD_BYTES = 131072
MAX_JSON_DEPTH = 32


def _telemetry_status_for_tool_result(result: Any) -> int:
    """Derive a status code from tool.execute() return value for telemetry."""
    if isinstance(result, dict):
        if isinstance(result.get("status_code"), int):
            return result["status_code"]
        if "error" in result:
            return 500
    return 200


def json_max_depth(data: Any) -> int:
    """
    Compute maximum nesting depth for JSON-like data structures.
    """
    if not isinstance(data, (dict, list)):
        return 1

    max_depth = 1
    stack: List[Tuple[Any, int]] = [(data, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            max_depth = depth

        if isinstance(current, dict):
            for value in current.values():
                if isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))
        elif isinstance(current, list):
            for value in current:
                if isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))

    return max_depth


def decode_jwt_no_verify(token: str):
    # JWT is header.payload.signature
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")

    # JWT uses base64url, which may be missing padding
    def b64url_decode(data: str) -> bytes:
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))

    return header, payload


def aud_allows_mcp(aud: Any) -> bool:
    if isinstance(aud, str):
        return aud.lower() == "mcp"
    if isinstance(aud, (list, tuple, set)):
        for entry in aud:
            if isinstance(entry, str) and entry.lower() == "mcp":
                return True
    return False


def is_sis_token(header: Dict[str, Any], payload: Dict[str, Any]) -> bool:
    token_type = header.get("token_type")
    if isinstance(token_type, str) and token_type.lower() == "sis":
        return True
    issuer = payload.get("iss")
    if isinstance(issuer, str) and "/sis" in issuer:
        return True
    return False


class MCPMessageHandler:
    """
    Handles MCP JSON-RPC message processing and response generation.

    This class provides a complete implementation of the MCP protocol,
    including request parsing, method routing, and response formatting.
    It supports the standard MCP methods: initialize, tools/list, and tools/call.

    Attributes:
        tool_manager: Instance of ToolManager for handling tool operations.
    """

    def __init__(self, tool_manager: ToolManager) -> None:
        """
        Initialize the MCP message handler.

        Args:
            tool_manager: ToolManager instance for tool operations.
        """
        self.tool_manager = tool_manager

    def parse_request(self, in_string: str) -> Tuple[int, JsonDict]:
        """
        Parse incoming HTTP request and extract RPC payload.

        This method validates the HTTP request structure, extracts the JSON-RPC
        payload, and prepares authentication tokens for subsequent processing.

        Args:
            in_string: Raw HTTP request string containing JSON data.

        Returns:
            Tuple containing:
                - int: HTTP status code (200 for success, 4xx/5xx for errors)
                - JsonDict: Parsed data or error response

        Raises:
            No exceptions are raised; all errors are returned as status codes.
        """
        try:
            request = json.loads(in_string)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in request: %s", e)
            return 400, {"error": "Invalid JSON format"}

        MCPSettings.set_splunkd_url_from_request(request)

        # Validate HTTP method
        http_method = request.get("method", "POST").upper()
        if http_method == "GET":
            logger.warning("GET method not allowed for MCP requests")
            return 405, {"message": "Method not allowed"}
        if http_method != "POST":
            logger.warning("Unsupported HTTP method: %s", http_method)
            return 405, {"message": f"HTTP method {http_method} not allowed"}

        # Extract and parse RPC payload
        raw_payload = request.get("payload", "")
        payload_size = (
            len(raw_payload.encode("utf-8"))
            if isinstance(raw_payload, str)
            else (
                len(raw_payload)
                if isinstance(raw_payload, bytes)
                else len(json.dumps(raw_payload).encode("utf-8"))
            )
        )
        if payload_size > MAX_PAYLOAD_BYTES:
            logger.warning(
                "Payload size %d exceeds max_payload_bytes=%d",
                payload_size,
                MAX_PAYLOAD_BYTES,
            )
            return 413, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Payload exceeds max_payload_bytes",
                },
            }

        try:
            rpc_req = (
                json.loads(raw_payload)
                if isinstance(raw_payload, (str, bytes))
                else raw_payload
            )
        except Exception as e:
            logger.error("Failed to parse RPC payload: %s", e)
            return 400, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }

        max_depth = json_max_depth(rpc_req)
        if max_depth > MAX_JSON_DEPTH:
            logger.warning(
                "JSON depth %d exceeds max_json_depth=%d",
                max_depth,
                MAX_JSON_DEPTH,
            )
            return 400, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "JSON payload exceeds max_json_depth",
                },
            }

        # Get auth token and traceparent from headers
        auth_token = ""
        traceparent = ""
        headers = request.get("headers", [])

        # Headers are in array format: [["Header-Name", "Header-Value"], ...]
        if isinstance(headers, list):
            for header_pair in headers:
                if isinstance(header_pair, list) and len(header_pair) >= 2:
                    header_name = header_pair[0].lower()
                    header_value = header_pair[1]
                    if header_name == AUTHORIZATION_HEADER_NAME and not auth_token:
                        auth_token = header_value
                    elif header_name == TRACEPARENT_HEADER_NAME and not traceparent:
                        traceparent = header_value

        update_log_context_traceparent(traceparent)

        # Extract bearer token
        if auth_token.lower().startswith("bearer ") or auth_token.lower().startswith(
            "splunk "
        ):
            auth_token = auth_token[7:].strip()
        else:
            # If auth token is Base64-encoded Basic Auth credentials, obtain token
            if auth_token.lower().startswith("basic "):
                try:
                    from splunk_api import call_splunk_api

                    b64_encoded = auth_token[6:].strip()
                    decoded_bytes = base64.b64decode(b64_encoded)
                    decoded_str = decoded_bytes.decode("utf-8")
                    # Basic auth format is "username:password"
                    parts = decoded_str.split(":", 1)
                    if len(parts) == 2:
                        username, password = parts
                        # Call Splunk /services/auth/login API with output_mode=json using call_splunk_api
                        api = "/services/auth/login"
                        params = {"output_mode": "json"}
                        data = {"username": username, "password": password}
                        response = call_splunk_api(
                            session_key="",  # No token yet
                            method="POST",
                            api=api,
                            headers={"Accept": "application/json"},
                            params=params,
                            data=data,
                        )
                        if response.status_code == 200:
                            resp_json = response.json()
                            auth_token = resp_json.get("sessionKey", "")
                            logger.info("Obtained sessionKey from Splunk login API")
                            if not auth_token:
                                logger.error(
                                    "sessionKey not found in Splunk JSON response"
                                )
                        else:
                            return response.status_code, {
                                "jsonrpc": "2.0",
                                "id": None,
                                "message": f"Authentication failed: {response.text}",
                            }
                except Exception as e:
                    return 401, {
                        "jsonrpc": "2.0",
                        "id": None,
                        "message": f"Authentication failed: {e}",
                    }

        logger.info("Request parsed successfully, method: %s", rpc_req.get("method"))
        return 200, {
            "rpc_request": rpc_req,
            "auth_token": auth_token,
            "full_request": request,
        }

    def handle_rpc_method(
        self,
        rpc_req: JsonDict,
        auth_token: str,
        system_authtoken: str,
        endpoint: str,
        validated_auth: Optional[
            Tuple[bool, Optional[str], Optional[Dict[str, Any]], Optional[str], bool]
        ] = None,
        rate_limits: Optional["RateLimits"] = None,
    ) -> Tuple[int, JsonDict]:
        """
        Route and handle specific RPC method calls.

        This method dispatches incoming RPC requests to the appropriate handler
        based on the method name. It provides comprehensive error handling and
        logging for all supported MCP methods.

        Args:
            rpc_req: JSON-RPC request object containing method and parameters.
            auth_token: Authentication token for Splunk API calls.
            system_authtoken: System authentication token from the full request.
            endpoint: The REST endpoint being accessed.
            validated_auth: Optional tuple of (is_valid, username, claims,
                error_message, is_cui_token) from upstream token validation.
            rate_limits: Optional rate-limit state for the current request.

        Returns:
            Tuple containing:
                - int: HTTP status code
                - JsonDict: JSON-RPC response or error object
        """
        rpc_id = rpc_req.get("id", None)
        rpc_method = rpc_req.get("method")
        params = rpc_req.get("params", {}) or {}

        # Update logging context with RPC method information
        update_log_context(rpc_method=rpc_method, rpc_id=rpc_id)

        start_time = time.time()
        update_log_context(operation_type="rpc_request", operation_phase="start")
        logger.info("Operation started: rpc_request, method=%s", rpc_method)
        update_log_context(operation_type="rpc_request", operation_phase="in_progress")

        status_code: int = 500
        try:
            # No aud check for ping and list_tools

            # Ping method for health checks
            # Note: Not part of MCP spec, but useful for diagnostics
            if rpc_method == "ping":
                logger.info("Processing ping request")
                status_code = 200
                return status_code, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "result": {"message": "pong"},
                }

            # MCP Internal Methods, authentication required, capabilities and aud not checked

            # Validate token using MCPAuthorization, also decrypt token if needed
            if validated_auth is None:
                validated_auth = MCPAuthorization.validate_token(
                    auth_token, system_authtoken
                )
            (
                is_valid,
                auth_token,
                user_info,
                error_message,
                was_cui_exchange,
            ) = validated_auth
            if not is_valid:
                log_telemetry(
                    EVENT_AUTH_FAILURE,
                    http.HTTPStatus.UNAUTHORIZED,
                    error_message=error_message,
                )
                logger.warning("Token validation failed: %s", error_message)
                status_code = 401
                return status_code, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32600,
                        "message": f"Authentication failed: {error_message}",
                    },
                }

            # Update logging context with user information
            if user_info:
                update_log_context(username=user_info.get("username"))
                logger.info(
                    "Token validated successfully for user: %s",
                    user_info.get("username"),
                )

            # Decode JWT without verification to check 'aud' claim
            # Skip aud check for exchanged CUI tokens and SIS-minted tokens
            if not was_cui_exchange:
                try:
                    header, payload = decode_jwt_no_verify(auth_token)
                    if not is_sis_token(header, payload):
                        aud = payload.get("aud")
                        if not aud_allows_mcp(aud):
                            log_telemetry(
                                EVENT_AUTH_INVALID_AUDIENCE,
                                http.HTTPStatus.FORBIDDEN,
                                error_message=f"Invalid token audience: {aud}",
                            )
                            logger.warning("Invalid token audience: %s", aud)
                            status_code = 403
                            return status_code, {
                                "jsonrpc": "2.0",
                                "id": rpc_id,
                                "error": {
                                    "code": -32600,
                                    "message": f"Invalid token audience: {aud}",
                                },
                            }
                except Exception as e:
                    log_telemetry(
                        EVENT_AUTH_TOKEN_DECODE_ERROR,
                        http.HTTPStatus.FORBIDDEN,
                        error_message=str(e),
                        error_type=type(e).__name__,
                    )
                    logger.error("Failed to decode bearer token: %s", e)
                    status_code = 403
                    return status_code, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "error": {
                            "code": -32600,
                            "message": "Failed to decode bearer token",
                        },
                    }

            # Check if the user has MCP capability
            has_capability, cap_error = MCPAuthorization.check_user_capabilities(
                user_info, ["mcp_tool_execute"]
            )
            if not has_capability:
                log_telemetry(
                    EVENT_AUTH_ACCESS_DENIED,
                    http.HTTPStatus.FORBIDDEN,
                    error_message=cap_error,
                )
                logger.warning("User lacks required MCP capabilities: %s", cap_error)
                status_code = 403
                return status_code, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32600,
                        "message": "User lacks required mcp_tool_execute capability",
                    },
                }

            log_telemetry(EVENT_AUTH_SUCCESS, http.HTTPStatus.OK)

            if rpc_method == "initialize":
                status_code, result = self._dispatch_with_telemetry(
                    EVENT_INITIALIZE_COMPLETE,
                    self._handle_initialize,
                    rpc_id,
                )
                return status_code, result
            if rpc_method == "tools/list":
                status_code, result = self._dispatch_with_telemetry(
                    EVENT_TOOLS_LIST_COMPLETE,
                    self._handle_tools_list,
                    rpc_id,
                    auth_token,
                    system_authtoken,
                )
                return status_code, result
            if rpc_method == "tools/call":
                status_code, result = self._handle_tools_call(
                    rpc_id, params, auth_token, system_authtoken, rate_limits
                )
                return status_code, result
            if rpc_method == "notifications/initialized":
                logger.info("Processing notifications/initialized request")
                status_code = 200
                log_telemetry(EVENT_NOTIFICATION_RECEIVED, http.HTTPStatus.OK)
                return status_code, None
            else:
                logger.info("Unknown RPC method requested: %s", rpc_method)
                status_code = 200
                return status_code, {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method '{rpc_method}' not found",
                    },
                }
        except Exception as e:
            logger.exception("Internal error dispatching method %s: %s", rpc_method, e)
            return 500, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32603, "message": "Internal error"},
            }
        finally:
            execution_time = time.time() - start_time
            update_log_context(
                operation_type="rpc_request",
                operation_phase="end",
                status=status_code,
                execution_time_seconds=round(execution_time, 3),
            )
            if status_code >= 400:
                logger.error(
                    "Operation completed with error: rpc_request, method=%s", rpc_method
                )
            else:
                logger.info("Operation completed: rpc_request, method=%s", rpc_method)

    def _dispatch_with_telemetry(
        self, event_type: str, handler: Any, *args: Any
    ) -> Tuple[int, JsonDict]:
        """Call *handler* and emit a telemetry event using the handler's status code."""
        try:
            result = handler(*args)
            status = result[0] if isinstance(result, tuple) else http.HTTPStatus.OK
            log_telemetry(event_type, status)
            return result
        except Exception as e:
            log_telemetry(
                event_type,
                http.HTTPStatus.INTERNAL_SERVER_ERROR,
                error_type=type(e).__name__,
                error_message=str(e),
            )
            raise

    def _handle_initialize(self, rpc_id: RpcId) -> Tuple[int, JsonDict]:
        """
        Handle the 'initialize' RPC method.

        This method returns server capabilities and metadata as required
        by the MCP protocol initialization sequence.

        Args:
            rpc_id: JSON-RPC request identifier.

        Returns:
            Tuple containing status code and initialization response.
        """
        logger.info("Processing initialize request")

        settings = MCPSettings.get()
        content = {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": settings.app_name,
                    "version": settings.app_version,
                },
            },
        }

        logger.info("Initialize request completed successfully")
        return 200, content

    def _handle_tools_list(
        self, rpc_id: RpcId, auth_token: str, system_authtoken: str
    ) -> Tuple[int, JsonDict]:
        """
        Handle the 'tools/list' RPC method.

        This method returns a list of all available tools that are currently
        enabled in the system.

        Args:
            rpc_id: JSON-RPC request identifier.

        Returns:
            Tuple containing status code and tools list response.
        """
        logger.info("Processing tools/list request")

        # Get a list of installed application
        installed_apps = get_installed_apps(auth_token)
        logger.info("Installed apps: %s", installed_apps)

        if "error" in installed_apps:
            status_code = installed_apps.get(
                "status_code", http.HTTPStatus.INTERNAL_SERVER_ERROR
            )
            logger.error(
                "tools/list aborted: apps lookup failed (status=%s): %s",
                status_code,
                installed_apps["error"],
            )
            return status_code, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32603,
                    "message": f"Failed to retrieve installed apps: {installed_apps['error']}",
                },
            }

        # Ensure enabled tool map is refreshed using the system session key so
        # KV-backed enablement state is honored.
        try:
            self.tool_manager.refresh_tools_for_listing(system_authtoken)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to refresh tools with system auth token: %s", exc)

        tools = self.tool_manager.list_tools(
            enabled_only=True, installed_apps=set(installed_apps.get("apps", []))
        )
        content = build_call_tool_message(tools, rpc_id=rpc_id)

        logger.info("Tools list request completed, %d tools available", len(tools))
        return 200, content

    def _handle_tools_call(
        self,
        rpc_id: RpcId,
        params: JsonDict,
        auth_token: str,
        system_authtoken: str,
        rate_limits: Optional["RateLimits"] = None,
    ) -> Tuple[int, JsonDict]:
        """
        Handle the 'tools/call' RPC method.

        This method executes a specific tool with provided arguments and
        returns the result in the proper MCP format.

        Args:
            rpc_id: JSON-RPC request identifier.
            params: Parameters containing tool name and arguments.
            auth_token: Authentication token for tool execution.

        Returns:
            Tuple containing status code and tool execution response.
        """
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        update_log_context(tool_name=tool_name)

        logger.info("Processing tools/call request for tool: %s", tool_name)

        if not tool_name:
            logger.error("Tool name missing in tools/call request")
            return 400, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {"code": -32602, "message": "Missing tool name"},
            }

        try:
            tool = self.tool_manager.get_enabled_tool(tool_name, system_authtoken)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Failed to verify tool is enabled: %s", exc)
            return 500, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32603,
                    "message": "Unable to verify tool availability",
                },
            }

        # Tool not in memory — try refreshing custom tools (may be newly added)
        if not tool:
            try:
                self.tool_manager.refresh_custom_tools(system_authtoken)
                tool = self.tool_manager.get_enabled_tool(tool_name, system_authtoken)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to refresh custom tools: %s", exc)

        if not tool:
            logger.error("Tool not found: %s", tool_name)
            return 404, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32004,
                    "message": f"Tool '{tool_name}' not found",
                },
            }

        rate_limit_error = self._check_rate_limit(
            rpc_id, tool_name, tool.tool_id, system_authtoken, rate_limits
        )
        if rate_limit_error:
            return rate_limit_error

        start = time.time()
        try:
            result = tool.execute(auth_token, tool_args)
            # to indicate that telemetry was already emitted upstream so we don't double-count the same event
            suppress = isinstance(result, dict) and result.pop(
                TELEMETRY_SUPPRESS_KEY, False
            )
            if not suppress:
                log_telemetry(
                    EVENT_TOOL_CALL_COMPLETE,
                    _telemetry_status_for_tool_result(result),
                    execution_time_seconds=round(time.time() - start, 3),
                )
            return self._format_tool_result(rpc_id, result)
        except Exception as e:
            log_telemetry(
                EVENT_TOOL_CALL_ERROR,
                http.HTTPStatus.INTERNAL_SERVER_ERROR,
                execution_time_seconds=round(time.time() - start, 3),
                error_type=type(e).__name__,
                error_message=str(e),
            )
            logger.exception("Tool execution failed for %s: %s", tool_name, e)
            return 200, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{"type": "text", "text": str(e)}],
                    "isError": True,
                },
            }

    def _check_rate_limit(
        self,
        rpc_id: RpcId,
        tool_name: str,
        tool_id: str,
        system_authtoken: str,
        rate_limits: Optional["RateLimits"] = None,
    ) -> Tuple[int, JsonDict] | None:
        """
        Enforce rate limits for a tool call.

        Returns an error response tuple if the limit is exceeded or an internal
        error occurs, or None if the request is allowed to proceed.
        """
        try:
            rate_limit_manager = RateLimitManager(session_key=system_authtoken)
            rate_limit_manager.enforce_rate_limits(
                tool_id=tool_id, rate_limits=rate_limits
            )
        except RateLimitCounterExceeded as exc:
            log_telemetry(
                EVENT_TOOL_RATE_LIMIT_EXCEEDED,
                http.HTTPStatus.TOO_MANY_REQUESTS,
                tool_name=tool_name,
            )
            logger.warning(f"Rate limit exceeded for tool {tool_name}: {exc}")
            return 429, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Rate limit key={exc.key} limit={exc.limit} exceeded during tool={tool_name} call.",
                        }
                    ],
                    "isError": True,
                },
            }
        except Exception as e:
            logger.exception(
                f"Rate limit enforcement failed for tool {tool_name} with error: {e}"
            )
            return 500, {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "error": {
                    "code": -32603,
                    "message": "Rate limit enforcement failed with an internal error",
                },
            }
        return None

    def _format_tool_result(self, rpc_id: RpcId, result: Any) -> Tuple[int, JsonDict]:
        """
        Format tool execution result into proper MCP response format.

        This method handles both successful results and error conditions,
        ensuring proper JSON serialization and MCP-compliant formatting.

        Args:
            rpc_id: JSON-RPC request identifier.
            result: Raw result from tool execution.

        Returns:
            Tuple containing status code and formatted response.
        """
        if isinstance(result, dict) and "error" in result:
            logger.info("Formatting error result for RPC %s", rpc_id)
            content = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result.get("error", "Tool execution error"),
                        }
                    ],
                    "isError": True,
                },
            }
        else:
            logger.info("Formatting success result for RPC %s", rpc_id)
            # Serialize result for text content
            try:
                serialized = json.dumps(result, separators=(",", ":"))
            except Exception as e:
                logger.warning("Failed to serialize result as JSON: %s", e)
                serialized = str(result)

            # Ensure structured content is properly formatted
            structured = result if isinstance(result, dict) else {"value": result}

            content = {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [{"type": "text", "text": serialized}],
                    "structuredContent": structured,
                },
            }

        return 200, content


def _arg_to_schema(arg: ToolArgument) -> JsonDict:
    """
    Convert a ToolArgument into JSON Schema property definition.

    This function extracts type information, validation rules, default values,
    and other metadata to create a proper JSON Schema property definition
    that can be used in MCP tool specifications.

    Args:
        arg: ToolArgument instance to convert.

    Returns:
        JsonDict containing JSON Schema property definition.
    """
    prop: JsonDict = {"type": arg.type.value}

    # Add description if available
    if arg.description:
        prop["description"] = arg.description

    # Add default value if provided
    if arg.default is not None:
        prop["default"] = arg.default

    # Add numeric bounds for number/integer types
    if arg.type in (ArgumentType.NUMBER, ArgumentType.INTEGER):
        if arg.min is not None:
            prop["minimum"] = arg.min
        if arg.max is not None:
            prop["maximum"] = arg.max

    # Add enumeration values if specified
    if arg.enum is not None:
        enum_vals = list(arg.enum)
        if enum_vals:
            prop["enum"] = enum_vals

    # Add placeholder as example
    if arg.placeholder is not None and str(arg.placeholder).strip():
        examples = prop.get("examples", [])
        examples.append(arg.placeholder)
        prop["examples"] = examples

    # Add validation pattern if specified
    validation = getattr(arg, "validation", None)
    pattern = getattr(validation, "pattern", None) if validation else None
    if pattern:
        prop["pattern"] = pattern
        message = getattr(validation, "message", None)
        if message:
            desc = prop.get("description", "")
            prop["description"] = (
                desc + ("\n" if desc else "") + f"Validation: {message}"
            ).strip()

    return prop


def _tool_to_public_dict(tool: Tool) -> JsonDict:
    """
    Convert internal Tool object to public tool description with inputSchema.

    This function transforms internal tool representations into the format
    required by the MCP protocol, including proper JSON Schema generation
    for tool arguments.

    Args:
        tool: Tool instance or dict to convert.

    Returns:
        JsonDict containing public tool description with input schema.
    """
    # Handle both Tool objects and pre-serialized dicts
    if isinstance(tool, dict):
        name = tool.get("name")
        description = tool.get("description", "")
        args_iter = tool.get("arguments", [])
        args_objects = list(args_iter)
    else:
        name = getattr(tool, "name")
        description = getattr(tool, "description", "")
        args_objects = getattr(tool, "arguments", [])

    properties: JsonDict = {}
    required: List[str] = []

    # Process each argument to build schema properties
    for arg in args_objects:
        if isinstance(arg, dict):
            # Handle dict-style arguments
            arg_name = arg.get("name")
            if not arg_name:
                continue

            # Create temporary object for schema conversion
            fake_arg = type("Arg", (), arg)
            schema = _arg_to_schema(fake_arg)  # type: ignore[arg-type]
            properties[arg_name] = schema

            if arg.get("required"):
                required.append(arg_name)
        else:
            # Handle ToolArgument objects
            arg_name = getattr(arg, "name", None)
            if not arg_name:
                continue

            properties[arg_name] = _arg_to_schema(arg)
            if getattr(arg, "required", False):
                required.append(arg_name)

    # Build complete input schema
    input_schema: JsonDict = {
        "type": "object",
        "properties": properties,
    }
    if required:
        input_schema["required"] = required

    return {
        "name": name,
        "description": description,
        "inputSchema": input_schema,
    }


def build_call_tool_message(tools: Iterable[Tool], rpc_id: RpcId) -> JsonDict:
    """
    Build a JSON-RPC 2.0 response listing available tools.

    This function creates a properly formatted MCP tools/list response
    containing all available tools with their schemas and metadata.

    Args:
        tools: Iterable of Tool objects or pre-serialized dicts.
        rpc_id: JSON-RPC request identifier to echo back.

    Returns:
        JsonDict matching the JSON-RPC 2.0 response format.
    """
    tool_list = [_tool_to_public_dict(tool) for tool in tools]
    logger.info("Built tool list message with %d tools", len(tool_list))

    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": {"tools": tool_list},
    }


# Public API exports
__all__ = [
    "MCPMessageHandler",
    "build_call_tool_message",
]
