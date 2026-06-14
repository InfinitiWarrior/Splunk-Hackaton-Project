"""
MCP Settings — singleton dataclass holding all application configuration.

This module defines the MCPSettings dataclass and its initialization phases:

- **Static**: Bundled JSON files loaded eagerly at process start.
- **Request-derived**: ``splunkd_url`` set from ``server.rest_uri`` on first request.
- **Conf**: ``.conf`` values read via Splunk REST API once a system service
  is available.

All parsing and file-loading utilities live in ``conf_util.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, Optional, Set

from conf_util import load_conf_into, load_generating_commands, load_safe_spl_config
from constants import SPLUNK_MCP_SERVER_APP
from http_utils import extract_rest_uri
from logging_config import get_logger

logger = get_logger(__name__)

# Singleton storage
_singleton_instance: Optional["MCPSettings"] = None


@dataclass
class MCPSettings:
    """Application configuration for the MCP Splunk Server.

    Static: loaded eagerly from bundled JSON files.
    Request-derived: splunkd_url from server.rest_uri.
    Conf: loaded from mcp.conf/app.conf via Splunk REST API.
    """

    # ------------------------------------------------------------------
    # Static — loaded once at startup from bundled JSON files.
    # Populated by _load_static_config() via load_safe_spl_config() and
    # load_generating_commands() in conf_util.py.
    # Source files: default/safe_spl.json, default/generating_commands.json
    # ------------------------------------------------------------------
    safe_spl_commands: Set[str] = field(default_factory=set)
    generating_commands: Set[str] = field(default_factory=set)
    safe_spl_exclude_tools: Set[str] = field(default_factory=set)
    sub_search_arg_cmd: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Request-derived — extracted from the incoming REST request payload.
    # Updated by set_splunkd_url_from_request() on every request; only changes when
    # the value in request["server"]["rest_uri"] differs from current.
    # ------------------------------------------------------------------
    splunkd_url: Optional[str] = None

    # ------------------------------------------------------------------
    # Conf — read from mcp.conf [server] stanza and app.conf via Splunk
    # REST API.  Populated by load_splunk_conf() → load_conf_into() once a Splunk
    # service object is available.  Values below are safe defaults used
    # until load_splunk_conf() completes successfully.
    # ------------------------------------------------------------------

    # mcp.conf [server] timeout — HTTP timeout in seconds applied to all
    # outbound requests (splunkd REST API calls and JWKS fetches).
    timeout: float = 60.0

    # app.conf [id] name
    app_name: str = SPLUNK_MCP_SERVER_APP

    # app.conf [id] version
    app_version: str = "1.1.3"

    # mcp.conf [server] max_row_limit
    max_row_limit: int = 1000

    # mcp.conf [server] default_row_limit
    default_row_limit: int = 100

    # mcp.conf [server] require_encrypted_token
    require_encrypted_token: bool = True

    # mcp.conf [server] legacy_token_grace_days (min: 0)
    legacy_token_grace_days: int = 180

    # mcp.conf [server] mcp_token_max_lifetime_seconds (must be positive)
    mcp_token_max_lifetime_seconds: int = 15552000  # 180 days

    # mcp.conf [server] mcp_token_default_lifetime_seconds (clamped to max)
    mcp_token_default_lifetime_seconds: int = 15552000

    # mcp.conf [server] token_key_reload_interval_seconds (min: 0.0)
    token_key_reload_interval_seconds: float = 0.0

    # CUI (Common User Interface) JWT validation settings
    # All read from mcp.conf [server] stanza via load_cui_settings()
    # mcp.conf [server] cui_enforce_jwt_validation
    cui_enforce_jwt_validation: bool = True

    # mcp.conf [server] cui_allowed_issuers (CSV, trailing slashes stripped)
    cui_allowed_issuers: Set[str] = field(default_factory=set)

    # mcp.conf [server] cui_allowed_audiences (CSV)
    cui_allowed_audiences: Set[str] = field(default_factory=set)

    # mcp.conf [server] cui_allowed_jwt_algs (CSV, uppercased; defaults to RS256)
    cui_allowed_jwt_algs: Set[str] = field(default_factory=lambda: {"RS256"})

    # mcp.conf [server] cui_jwks_by_issuer (JSON dict: issuer → JWKS URL)
    cui_jwks_by_issuer: Dict[str, str] = field(default_factory=dict)

    # mcp.conf [server] cui_jwt_clock_skew_seconds (min: 0)
    cui_jwt_clock_skew_seconds: int = 60

    # Tool collision detection threshold (not currently in .conf; hardcoded)
    jaccard_similarity_threshold: float = 0.8

    # ------------------------------------------------------------------
    # Internal class state
    # ------------------------------------------------------------------
    _conf_loaded: ClassVar[bool] = False

    # ==================================================================
    # Public API
    # ==================================================================

    @classmethod
    def get(cls) -> "MCPSettings":
        """Get or create the singleton instance."""
        global _singleton_instance
        if _singleton_instance is None:
            _singleton_instance = cls._load_static_config()
        return _singleton_instance

    @classmethod
    def set_splunkd_url_from_request(cls, request: Optional[Dict[str, Any]]) -> None:
        """Derive splunkd_url from server.rest_uri in the incoming request.

        Called on every request; only updates state when the URL changes.
        """
        if not request or not _singleton_instance:
            return

        rest_uri = extract_rest_uri(request)
        if not rest_uri:
            return

        splunkd_url = rest_uri.rstrip("/") + "/"
        if _singleton_instance.splunkd_url != splunkd_url:
            _singleton_instance.splunkd_url = splunkd_url
            logger.info("Updated splunkd_url to %s", splunkd_url)

    @classmethod
    def load_splunk_conf(cls, service: Any) -> None:
        """Read .conf settings via Splunk REST API (idempotent).

        Should be called once a system-level service is available.
        Subsequent calls are no-ops.
        """
        if cls._conf_loaded:
            return
        if service is None:
            logger.warning(
                "Cannot load .conf settings: Splunk service is not available"
            )
            return

        instance = cls.get()
        logger.info("Loading configuration from mcp.conf/app.conf via Splunk REST API")
        try:
            load_conf_into(instance, service)
            cls._conf_loaded = True
            logger.info("Configuration loaded successfully from Splunk .conf files")
        except Exception:
            logger.exception(
                "Failed to load .conf settings via Splunk REST API; using defaults"
            )

    @classmethod
    def reset_singleton(cls) -> None:
        """Reset the singleton instance (testing only)."""
        global _singleton_instance
        _singleton_instance = None
        cls._conf_loaded = False

    # ==================================================================
    # Static — eager initialization from bundled JSON files
    # ==================================================================

    @classmethod
    def _load_static_config(cls) -> "MCPSettings":
        """Create singleton with static settings from bundled JSON files."""
        logger.info("Initializing static configuration from bundled JSON files")

        safe_spl_commands, safe_spl_exclude_tools, sub_search_arg_cmd = (
            load_safe_spl_config()
        )
        generating_commands = load_generating_commands()

        cls._conf_loaded = False
        return cls(
            safe_spl_commands=safe_spl_commands,
            generating_commands=generating_commands,
            safe_spl_exclude_tools=safe_spl_exclude_tools,
            sub_search_arg_cmd=sub_search_arg_cmd,
        )
