from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from urllib.parse import parse_qs

from splunk.persistconn.application import PersistentServerConnectionApplication

# Ensure the current directory is on sys.path for local imports
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from crypto import TokenCrypto
from logging_config import get_logger
from settings import MCPSettings
from splunk_api import call_splunk_api

# Module logger
logger = get_logger(__name__)


class MCPTokenHandler(PersistentServerConnectionApplication):
    """
    REST endpoint for creating encrypted MCP tokens.

    This handler provides a simple GET endpoint that creates a Splunk JWT token
    with audience 'mcp', encrypts it, and returns it to the caller.
    """

    def __init__(self, command_line: str, command_arg: str) -> None:
        """Initialize the MCP token handler."""
        super().__init__()
        self.settings = MCPSettings.get()

    def handle(self, in_string: str) -> Dict[str, Any]:
        """
        Handle incoming HTTP requests.

        Supports GET requests with query parameters:
            - username: (required) The user to create the token for
            - expires_on: Token expiration time (e.g., "+30d", "+1h", or ISO datetime)
            - not_before: Token not valid before time (e.g., "+0d", or ISO datetime)

        Args:
            in_string: Raw HTTP request string containing JSON data.

        Returns:
            Dict containing HTTP response with status, headers, and payload.
        """
        logger.info("Received MCP token request")

        try:
            request = json.loads(in_string)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in request: %s", e)
            return self._build_response(400, {"error": "Invalid JSON format"})

        method = request.get("method", "GET").upper()

        # Preserve request context for settings (splunkd_url/ssl decisions)
        MCPSettings.set_splunkd_url_from_request(request)

        # Get session token (from requireAuthentication=true and passSession=true)
        session = request.get("session") or {}
        auth_token = session.get("authtoken", "")

        if not auth_token:
            logger.error("No session token available")
            return self._build_response(401, {"error": "Authentication required"})

        # Get system auth token for initializing crypto
        system_authtoken = (
            request.get("system_authtoken")
            or request.get("systemAuthtoken")
            or auth_token
        )

        # Parse query parameters
        query_params = self._parse_query_params(request.get("query", []))
        form_params = self._parse_query_params(request.get("form", {}))

        controls_ok, controls_error = self._validate_security_controls()
        if not controls_ok:
            logger.error(
                "mcp_token security controls validation failed: %s", controls_error
            )
            return self._build_response(412, {"error": controls_error})

        if method == "POST":
            payload = self._parse_payload(request.get("payload"))
            action = None
            if isinstance(payload, dict):
                action = payload.get("action")
            action = action or form_params.get("action") or query_params.get("action")

            if action != "rotate":
                return self._build_response(
                    400,
                    {"error": "Unsupported action. Use action=rotate."},
                )

            key_size_raw = query_params.get("key_size") or form_params.get("key_size")
            if isinstance(payload, dict) and "key_size" in payload:
                key_size_raw = payload.get("key_size")
            key_size = 2048
            if key_size_raw:
                try:
                    key_size = int(key_size_raw)
                except (TypeError, ValueError):
                    return self._build_response(
                        400, {"error": "key_size must be an integer"}
                    )
            if key_size not in (2048, 4096):
                return self._build_response(
                    400, {"error": "key_size must be 2048 or 4096"}
                )

            rotated_at = TokenCrypto.get_instance().rotate_keys(
                system_authtoken,
                key_size=key_size,
                previous_key_grace_days=self.settings.legacy_token_grace_days,
            )
            fingerprint = TokenCrypto.get_instance().get_public_key_fingerprint()
            return self._build_response(
                200,
                {
                    "status": "rotated",
                    "key_size": key_size,
                    "rotated_at": rotated_at,
                    "public_key_fingerprint": fingerprint,
                },
            )

        # Initialize TokenCrypto for token minting
        tc = TokenCrypto.get_instance()
        try:
            tc.configure_reload_interval(
                self.settings.token_key_reload_interval_seconds
            )
        except Exception:
            pass

        if not tc.initialize(system_authtoken):
            logger.error("Failed to initialize TokenCrypto")
            return self._build_response(500, {"error": "Internal server error"})

        # Username is required
        username = query_params.get("username", "").strip()
        if not username:
            logger.error("Username missing in request")
            return self._build_response(400, {"error": "Missing username parameter"})

        # Build token payload
        token_payload: Dict[str, Any] = {
            "name": username,
            "audience": "mcp",
        }

        expires_on = query_params.get("expires_on")
        if not expires_on:
            expires_on = f"+{self.settings.mcp_token_default_lifetime_seconds}s"
        is_valid_expires_on, expires_on_error = self._validate_expires_on(expires_on)
        if not is_valid_expires_on:
            logger.warning(
                "Rejected mcp_token request due to invalid expires_on: %s",
                expires_on_error,
            )
            return self._build_response(400, {"error": expires_on_error})
        token_payload["expires_on"] = expires_on

        # Add optional parameters if provided
        if "not_before" in query_params:
            token_payload["not_before"] = query_params["not_before"]

        not_before = token_payload.get("not_before")
        if not_before:
            ordering_ok, ordering_error = self._validate_not_before_before_expires(
                not_before=not_before,
                expires_on=expires_on,
            )
            if not ordering_ok:
                logger.warning(
                    "Rejected mcp_token request due to invalid not_before/expires_on ordering"
                )
                return self._build_response(400, {"error": ordering_error})

        # Create token via Splunk REST API
        try:
            response = call_splunk_api(
                session_key=auth_token,
                method="POST",
                api="services/authorization/tokens",
                params={"output_mode": "json"},
                data=token_payload,
            )
        except Exception as exc:
            logger.exception("Failed to call Splunk token API: %s", exc)
            return self._build_response(500, {"error": "Token creation failed"})

        if response.status_code not in (200, 201):
            logger.error(
                "Token creation failed: status %d body %s",
                response.status_code,
                response.text,
            )
            return self._build_response(
                response.status_code,
                {"error": f"Token creation failed: {response.text}"},
            )

        # Extract token from response
        try:
            body = response.json()
            token_entries = body.get("entry", [])
            token_value = (
                token_entries[0].get("content", {}).get("token")
                if token_entries
                else None
            )
        except Exception as exc:
            logger.error("Failed to parse token response: %s", exc)
            token_value = None

        if not token_value:
            logger.error("Token value missing from Splunk response")
            return self._build_response(500, {"error": "Token not returned by Splunk"})

        # Encrypt the token
        try:
            encrypted_token = TokenCrypto.get_instance().encrypt(token_value)
        except Exception as exc:
            logger.exception("Failed to encrypt token: %s", exc)
            return self._build_response(500, {"error": "Token encryption failed"})

        logger.info("Encrypted token created for user %s with audience mcp", username)
        return self._build_response(200, {"token": encrypted_token})

    def _parse_query_params(self, query: Any) -> Dict[str, str]:
        """
        Parse query parameters from Splunk's format.

        Args:
            query: List of query parameter pairs [["key", "value"], ...]

        Returns:
            Dict of parameter names to values.
        """
        params = {}
        if isinstance(query, dict):
            return {str(k): v for k, v in query.items()}
        if isinstance(query, list):
            for pair in query:
                if isinstance(pair, list) and len(pair) >= 2:
                    params[str(pair[0])] = pair[1]
        elif isinstance(query, str):
            parsed = parse_qs(query, keep_blank_values=True)
            for key, values in parsed.items():
                if values:
                    params[key] = values[0]
        return params

    def _is_valid_encrypted_token(self, token: Any) -> bool:
        """
        Validate an encrypted token format (base64 segments separated by '.').
        """
        if not isinstance(token, str):
            return False
        if "\n" in token or "\r" in token:
            return False
        token = token.strip()
        if not token:
            return False
        segments = token.split(".")
        for segment in segments:
            if not segment:
                return False
            try:
                base64.b64decode(segment, validate=True)
            except Exception:
                return False
        return True

    def _parse_payload(self, payload: Any) -> Any:
        if payload is None or isinstance(payload, (dict, list)):
            return payload
        if isinstance(payload, str):
            payload = payload.strip()
            if not payload:
                return None
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                parsed = parse_qs(payload, keep_blank_values=True)
                if parsed:
                    return {k: v[0] if v else "" for k, v in parsed.items()}
                return payload
        return payload

    def _build_response(self, status: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Build HTTP response."""
        return {
            "status": status,
            "headers": {"Content-Type": "application/json"},
            "payload": payload,
        }

    def _validate_security_controls(self) -> tuple[bool, str]:
        """
        Fail closed when required token controls are not enabled.
        """
        if not self.settings.require_encrypted_token:
            return (
                False,
                "require_encrypted_token must be true before minting or rotating MCP tokens.",
            )
        if self.settings.mcp_token_max_lifetime_seconds <= 0:
            return (
                False,
                "mcp_token_max_lifetime_seconds must be a positive integer.",
            )
        if self.settings.mcp_token_default_lifetime_seconds <= 0:
            return (
                False,
                "mcp_token_default_lifetime_seconds must be a positive integer.",
            )
        if (
            self.settings.mcp_token_default_lifetime_seconds
            > self.settings.mcp_token_max_lifetime_seconds
        ):
            return (
                False,
                "mcp_token_default_lifetime_seconds must be less than or equal to mcp_token_max_lifetime_seconds.",
            )
        return True, ""

    def _validate_expires_on(self, expires_on: Any) -> tuple[bool, str]:
        if not isinstance(expires_on, str) or not expires_on.strip():
            return False, "expires_on must be a non-empty string."

        expires_on = expires_on.strip()
        lifetime_seconds = self._parse_relative_duration_seconds(expires_on)
        if lifetime_seconds is None:
            expires_at = self._parse_iso8601_utc(expires_on)
            if expires_at is None:
                return (
                    False,
                    "expires_on must be a relative value like '+30m' or '+1h', or an ISO-8601 datetime.",
                )
            now = datetime.now(timezone.utc)
            lifetime_seconds = int((expires_at - now).total_seconds())
            if lifetime_seconds <= 0:
                return False, "expires_on must be in the future."

        if lifetime_seconds > self.settings.mcp_token_max_lifetime_seconds:
            return (
                False,
                (
                    "expires_on exceeds allowed token lifetime "
                    f"({self.settings.mcp_token_max_lifetime_seconds}s)."
                ),
            )
        return True, ""

    def _validate_not_before_before_expires(
        self, not_before: Any, expires_on: Any
    ) -> tuple[bool, str]:
        if not isinstance(not_before, str) or not isinstance(expires_on, str):
            return (
                False,
                "not_before and expires_on must be strings when both are provided.",
            )

        not_before_at = self._parse_relative_or_iso_utc(not_before.strip())
        expires_at = self._parse_relative_or_iso_utc(expires_on.strip())
        if not_before_at is None or expires_at is None:
            # Skip strict ordering if we cannot parse one of the values here.
            return True, ""
        if not_before_at >= expires_at:
            return False, "not_before must be earlier than expires_on."
        return True, ""

    def _parse_relative_duration_seconds(self, value: str) -> Any:
        if not isinstance(value, str) or len(value) < 3 or not value.startswith("+"):
            return None

        unit = value[-1].lower()
        amount_part = value[1:-1]
        if unit not in {"s", "m", "h", "d"}:
            return None
        if not amount_part.isdigit():
            return None

        amount = int(amount_part)
        if unit == "s":
            return amount
        if unit == "m":
            return amount * 60
        if unit == "h":
            return amount * 3600
        if unit == "d":
            return amount * 86400
        return None

    def _parse_relative_or_iso_utc(self, value: str) -> Any:
        relative_seconds = self._parse_relative_duration_seconds(value)
        if relative_seconds is not None:
            return datetime.now(timezone.utc) + timedelta(seconds=relative_seconds)
        return self._parse_iso8601_utc(value)

    def _parse_iso8601_utc(self, value: str) -> Any:
        try:
            normalized = value
            if normalized.endswith("Z"):
                normalized = f"{normalized[:-1]}+00:00"
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None
