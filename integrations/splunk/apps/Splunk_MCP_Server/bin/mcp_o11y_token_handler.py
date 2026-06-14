import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

# Ensure the current directory is on sys.path for local imports
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

import splunklib.binding
from auth import exchange_cui_token
from base_rest_handler import BaseRestHandler
from constants import INTERNAL_SERVER_ERROR, METHOD_NOT_ALLOWED
from logging_config import get_logger
from o11y_token_exchange import O11Y_ACCESS_TOKEN, get_user_o11y_token
from settings import MCPSettings
from splunk.persistconn.application import PersistentServerConnectionApplication
from util.splunk_util import SplunkUtil

logger = get_logger(__name__)


class MCPO11yTokenHandler(BaseRestHandler, PersistentServerConnectionApplication):
    """
    REST endpoint for fetching Observability access tokens.

    This handler accepts a bearer token in the Authorization header. If the
    token is a Webex CUI JWT, it is exchanged for a Splunk access token before
    calling the /o11y-tokens endpoint. If the token is already a Splunk access
    token, it is used directly.
    """

    def __init__(self, command_line: str, command_arg: str) -> None:
        BaseRestHandler.__init__(self)
        self.settings = MCPSettings.get()

    def handle(self, in_string: str) -> Dict[str, Any]:
        logger.info("Received O11y token request")

        try:
            request = self.parse_request(in_string)
        except ValueError as e:
            logger.error("Invalid request: %s", e)
            return SplunkUtil.create_json_response(400, error="Invalid JSON format")

        method = request.get("method", "").upper()
        if method != "POST":
            return SplunkUtil.create_json_response(405, error=METHOD_NOT_ALLOWED)

        try:
            return self._handle_request(request)
        except Exception as exc:
            logger.exception("Unhandled error in o11y token handler: %s", exc)
            return SplunkUtil.create_json_response(500, error=INTERNAL_SERVER_ERROR)

    def _handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        MCPSettings.set_splunkd_url_from_request(request)

        auth_kwargs, auth_error = self._obtain_splunk_auth_kwargs(request)
        if auth_error is not None:
            return auth_error

        org_id = self._extract_org_id(request)
        service = self.initialize_user_service(auth_kwargs, request)

        # Try to generate a user-scoped o11y token using the session token.
        uid_result = self._try_session_token_exchange(service, org_id)
        if uid_result is not None:
            logger.info("Returning o11y UID token from session-token exchange")
            payload = self._build_o11y_tokens_payload(uid_result)
            return SplunkUtil.create_json_response(200, payload=payload)

        # Fallback to generating an org-scoped o11y token from the
        # services/o11y-tokens splunkd endpoint.
        return self._get_org_o11y_token(service)

    def _obtain_splunk_auth_kwargs(
        self, request: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
        """Obtain splunklib ``Service`` auth kwargs from the request.

        Accepts a bearer token in the ``Authorization`` header or a
        Splunk session cookie.

        Returns ``(auth_kwargs, None)`` on success — either
        ``{"splunkToken": ...}`` (Bearer) or ``{"token": ...}`` (Splunk).
        Returns ``(None, error_response)`` when the request cannot be
        authenticated.
        """
        header_auth = self.extract_bearer_token_and_scheme(request)

        if header_auth is not None:
            header_token, header_scheme = header_auth
            cui_ok, exchanged_token, cui_error = exchange_cui_token(header_token)
            if cui_ok and exchanged_token:
                logger.info("Exchanged CUI token to Splunk token")
                return {"splunkToken": exchanged_token}, None
            if cui_error and cui_error != "Not a CUI token":
                logger.warning("CUI token exchange failed: %s", cui_error)
                return None, SplunkUtil.create_json_response(
                    401, error=f"Authentication failed: {cui_error}"
                )
            logger.info("Using Splunk access token from header")
            kwarg = "splunkToken" if header_scheme == "bearer" else "token"
            return {kwarg: header_token}, None

        session_token = self._extract_session_token(request)
        if session_token:
            logger.info("Using Splunk access token from session")
            return {"token": session_token}, None

        logger.error("No bearer token provided")
        return None, SplunkUtil.create_json_response(
            401, error="Authentication required"
        )

    def _try_session_token_exchange(
        self, service: Any, org_id: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Create a user-scoped o11y token.

        Delegates to the ``o11y_token_exchange`` module. Returns the token
        exchange result on success, or ``None`` on any failure — so the
        caller can fall back to ``services/o11y-tokens`` splunkd endpoint.
        """
        try:
            return get_user_o11y_token(service, org_id=org_id)
        except Exception as exc:
            logger.warning(
                "O11y token exchange using session token failed, falling back "
                "to splunkd services/o11y-tokens endpoint: %s",
                exc,
            )
            return None

    def _get_org_o11y_token(self, service: Any) -> Dict[str, Any]:
        """Fetch an org-scoped o11y token from ``services/o11y-tokens`` splunkd endpoint."""
        logger.info("Falling back to org-scoped token via services/o11y-tokens")
        try:
            response = service.get("/services/o11y-tokens", output_mode="json")
        except splunklib.binding.HTTPError as exc:
            logger.error(
                "O11y token generation failed: status=%d reason=%s",
                exc.status,
                exc.reason,
            )
            return SplunkUtil.create_json_response(
                exc.status,
                error=f"O11y token generation failed: {exc.reason}",
            )
        except Exception as exc:
            logger.exception("O11y token generation failed: %s", exc)
            return SplunkUtil.create_json_response(
                500, error="O11y token generation failed"
            )

        try:
            payload = json.loads(response.body.read())
        except Exception as exc:
            logger.error("Failed to parse o11y token generation response: %s", exc)
            return SplunkUtil.create_json_response(
                500, error="Invalid o11y token generation response"
            )

        token_count = len(payload) if isinstance(payload, list) else "non-list"
        logger.info("org-scoped o11y-tokens response: %s token(s)", token_count)
        payload = self._mark_isuid_false(payload)
        return SplunkUtil.create_json_response(200, payload=payload)

    def _extract_session_token(self, request: Dict[str, Any]) -> Optional[str]:
        """Obtain the Splunk session token from the request."""
        try:
            return self._extract_user_session_token(request)
        except ValueError:
            return None

    def _extract_org_id(self, request: Dict[str, Any]) -> Optional[str]:
        """Extract the O11y org id from the request payload."""
        payload = request.get("payload")
        if isinstance(payload, str) and payload.strip():
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return None

        if not isinstance(payload, dict):
            return None

        org_id = payload.get("orgId") or payload.get("org_id")
        if not org_id:
            return None
        return str(org_id)

    def _build_o11y_tokens_payload(
        self, exchange_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Format the user-scoped O11y token into the response body.

        Wraps the user-scoped O11y token in a list
        (the same shape returned by the org-scoped fallback) and sets the
        ``isUID`` field to True.
        """
        access_token = exchange_result.get("o11yAccessToken") or {}
        pairings = exchange_result.get("pairingInfo") or []
        pairing = pairings[0] if pairings else {}

        token = access_token.get(O11Y_ACCESS_TOKEN)

        return [
            {
                "token": token,
                "realm": access_token.get("realm"),
                "status": "ACTIVE" if token else "INACTIVE",
                "orgName": pairing.get("ecTenantName") or "",
                "orgId": access_token.get("o11yOrgId") or "",
                "url": access_token.get("o11yOrgUrl") or pairing.get("orgUrl") or "",
                "isUID": True,
            }
        ]

    def _mark_isuid_false(self, payload: Any) -> Any:
        """
        Set the ``isUID`` field in the payload to False for the org-scoped token generation
        fallback so that clients can distinguish it from the user-scoped tokens.
        """
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    item["isUID"] = False
        return payload
