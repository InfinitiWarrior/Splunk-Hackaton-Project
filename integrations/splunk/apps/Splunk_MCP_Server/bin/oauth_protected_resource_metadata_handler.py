import os
import sys
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

# Add the directory where this script resides to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import splunklib
from base_rest_handler import AuthMode, BaseRestHandler
from conf_util import read_conf_value
from constants import INTERNAL_SERVER_ERROR, METHOD_NOT_ALLOWED, SPLUNK_MCP_SERVER_APP
from logging_config import get_logger
from splunk.persistconn.application import PersistentServerConnectionApplication
from util.splunk_util import SplunkUtil

logger = get_logger(__name__)


class OAuthProtectedResourceMetadataHandler(
    BaseRestHandler, PersistentServerConnectionApplication
):
    """
    Public endpoint that serves OAuth 2.0 Protected Resource Metadata (RFC 9728).

    https://datatracker.ietf.org/doc/html/rfc9728

    This endpoint is unauthenticated from the caller's perspective, so it uses a system token passed by Splunk (``passSystemAuth = true``) to read config.
    a system token passed by Splunk (``passSystemAuth = true``) to read config.

    PRM Document Shape
    ------------------
    RFC 9728 requires ``resource`` and allows optional fields including
    ``authorization_servers``.  We publish:

    - **resource** (required by RFC 9728): search-head public-facing URL.
    - **authorization_servers** (optional per RFC 9728, required by SIS):
      list of auth-server base URLs. Clients append
      ``/.well-known/openid-configuration`` to discover the full OAuth metadata.

    Example response::

        {
            "resource": "https://acme.splunkcloud.com",
            "authorization_servers": [
                "https://acme.scs.splunk.com/acme/sis/v1/rg/<resource_group>"
            ]
        }
    """

    AUTH_MODE = AuthMode.SYSTEM

    # Use app namespace so `service.confs[...]` resolves the effective
    # app-level configuration for this app, with Splunk's usual fallback behavior.
    SPLUNK_OWNER = "nobody"
    SPLUNK_APP = SPLUNK_MCP_SERVER_APP
    SPLUNK_SHARING = "app"

    # Splunk conf / stanza names used when reading configuration.
    _CONF_AUTHENTICATION = "authentication"
    _STANZA_AUTHENTICATION = "authentication"
    _STANZA_OAUTH2_SETTINGS = "oauth2_settings"
    _CONF_SERVER = "server"
    _STANZA_SCS = "scs"

    def __init__(self, command_line: str, command_arg: str) -> None:
        BaseRestHandler.__init__(self)
        self.command_line = command_line
        self.command_arg = command_arg

    def handle(self, in_string: str) -> Dict[str, Any]:
        try:
            request = self.parse_request(in_string)

            method = str(request.get("method", "")).upper()
            rest_path = str(request.get("rest_path", ""))

            logger.info(f"Received {method} {rest_path}")

            if method != "GET":
                return SplunkUtil.create_json_response(405, error=METHOD_NOT_ALLOWED)

            return self.handle_get(request)
        except splunklib.binding.HTTPError as exc:
            # Errors raised by the Splunk SDK / splunkd.
            logger.exception("Splunk SDK HTTP error")
            status = int(getattr(exc, "status", 500) or 500)
            reason = getattr(exc, "reason", str(exc))
            return SplunkUtil.create_json_response(status, error=str(reason))
        except ValueError as exc:
            # Invalid request structure, missing token, invalid config input, etc.
            logger.warning(f"Invalid request: {exc}")
            return SplunkUtil.create_json_response(400, error=str(exc))
        except Exception:
            logger.exception("Unexpected error in protected resource metadata handler")
            return SplunkUtil.create_json_response(500, error=INTERNAL_SERVER_ERROR)

    def handle_get(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build and return the protected resource metadata document.
        """
        self.initialize_system_service(request)
        logger.info("Splunk system service initialized for OAuth PRM request")

        issuer_uri = self._get_prm_issuer_uri()
        authorization_server = self._get_authorization_server_base_url()
        if not issuer_uri or not authorization_server:
            logger.warning(
                f"PRM not configured: issuer_uri={issuer_uri}, "
                f"authorization_server={authorization_server}"
            )
            return SplunkUtil.create_json_response(404, error="PRM not configured")

        parsed_rest_uri = urlsplit((request.get("server") or {}).get("rest_uri") or "")
        mgmt_port = str(parsed_rest_uri.port or "8089")
        resource_url = self._build_resource_url(issuer_uri, request, mgmt_port)

        metadata: Dict[str, Any] = {
            "resource": resource_url,
            "authorization_servers": [authorization_server],
        }

        logger.info(f"Returning PRM metadata for resource={resource_url}")
        return SplunkUtil.create_json_response(200, payload=metadata)

    @staticmethod
    def _build_resource_url(
        issuer_uri: str, request: Dict[str, Any], mgmt_port: str
    ) -> str:
        """Append the listening port to *issuer_uri* only when accessed via splunkd management port.

        RFC 9728 §3.3 requires ``resource`` to match the URL clients use.
        When a client hits splunkd directly (management port), the port must be
        reflected. On any other port (Splunk Web, reverse proxy) the issuer URI
        already encodes the correct public-facing address.
        """
        connection = request.get("connection") or {}
        port = connection.get("listening_port")

        if not port or str(port) != mgmt_port:
            return issuer_uri

        parsed = urlsplit(issuer_uri)
        return f"{parsed.scheme}://{parsed.hostname}:{port}"

    def _get_prm_issuer_uri(self) -> Optional[str]:
        """
        Read the issuer URI from authentication.conf.

        Expected key:
            [oauth2_settings]
            issuer_uri = https://acme.splunkcloud.com
        """
        issuer_uri = read_conf_value(
            self.system_service,
            self._CONF_AUTHENTICATION,
            self._STANZA_OAUTH2_SETTINGS,
            "issuer_uri",
        )
        if not issuer_uri:
            logger.info("issuer_uri not found in authentication.conf [oauth2_settings]")
            return None

        issuer_uri = issuer_uri.rstrip("/")
        logger.info(f"Read issuer_uri={issuer_uri}")
        return issuer_uri or None

    def _get_authorization_server_base_url(self) -> Optional[str]:
        """
        Derive the authorization server URL from Splunk config.

        Expected keys:
            server.conf [scs] tenantHostname
            server.conf [scs] tenant
            authentication.conf [authentication] resourceGroup
        """
        tenant_hostname = read_conf_value(
            self.system_service,
            self._CONF_SERVER,
            self._STANZA_SCS,
            "tenantHostname",
        )
        tenant = read_conf_value(
            self.system_service,
            self._CONF_SERVER,
            self._STANZA_SCS,
            "tenant",
        )
        resource_group = read_conf_value(
            self.system_service,
            self._CONF_AUTHENTICATION,
            self._STANZA_AUTHENTICATION,
            "resourceGroup",
        )

        logger.info(
            f"Config values: tenantHostname={tenant_hostname!r}, "
            f"tenant={tenant!r}, resourceGroup={resource_group!r}"
        )

        if not (tenant_hostname and tenant and resource_group):
            logger.error(
                "authorization_servers cannot be derived: one or more "
                "config values are missing."
            )
            return None

        tenant_hostname = self._normalize_host(tenant_hostname)
        if not tenant_hostname:
            logger.error(
                "authorization_servers cannot be derived: "
                "tenantHostname became empty after normalization."
            )
            return None

        return f"https://{tenant_hostname}/{tenant}/sis/v1/rg/{resource_group}"

    @staticmethod
    def _normalize_host(host_or_url: str) -> str:
        """
        Accept either a host or a URL and return only the host portion.

        Examples:
            acme.example.com           -> acme.example.com
            https://acme.example.com/ -> acme.example.com
        """
        host_or_url = host_or_url.strip().rstrip("/")

        if "://" not in host_or_url:
            return host_or_url.lstrip("/")

        parsed = urlsplit(host_or_url)
        return (parsed.netloc or parsed.path).lstrip("/")
