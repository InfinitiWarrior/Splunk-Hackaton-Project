"""
Shared utilities for reading and parsing Splunk configuration values.

Provides:
- REST API access: ``read_conf_value``, ``read_conf_stanza`` — read fully-resolved
  configuration through ``service.confs[...]`` (correct in clustered deployments).
- Value parsers: ``parse_bool``, ``parse_csv_to_set``, ``parse_json_dict`` —
  convert raw conf strings into typed Python values.
- Typed setters: ``set_conf_int``, ``set_conf_float``, ``set_conf_bool`` —
  apply parsed values to a dataclass instance with validation and logging.
- File helpers: ``find_app_file``, ``load_app_json`` — locate and load files
  from the app's local/default directories.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

from constants import (
    CONF_APP,
    CONF_KEY_CUI_ALLOWED_AUDIENCES,
    CONF_KEY_CUI_ALLOWED_ISSUERS,
    CONF_KEY_CUI_ALLOWED_JWT_ALGS,
    CONF_KEY_CUI_ENFORCE_JWT_VALIDATION,
    CONF_KEY_CUI_JWKS_BY_ISSUER,
    CONF_KEY_CUI_JWT_CLOCK_SKEW,
    CONF_KEY_DEFAULT_ROW_LIMIT,
    CONF_KEY_ID,
    CONF_KEY_LEGACY_TOKEN_GRACE_DAYS,
    CONF_KEY_MAX_ROW_LIMIT,
    CONF_KEY_MCP_TOKEN_DEFAULT_LIFETIME,
    CONF_KEY_MCP_TOKEN_MAX_LIFETIME,
    CONF_KEY_NAME,
    CONF_KEY_REQUIRE_ENCRYPTED_TOKEN,
    CONF_KEY_TIMEOUT,
    CONF_KEY_TITLE,
    CONF_KEY_TOKEN_KEY_RELOAD_INTERVAL,
    CONF_KEY_VERSION,
    CONF_MCP,
    STANZA_ID,
    STANZA_LAUNCHER,
    STANZA_PACKAGE,
    STANZA_SERVER,
)
from logging_config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# REST API conf readers
# ---------------------------------------------------------------------------


def read_conf_value(
    service: Any,
    conf_name: str,
    stanza: str,
    key: str,
) -> Optional[str]:
    """Read a single value from a Splunk .conf file via the REST API.

    Args:
        service: An initialized splunklib.client.Service.
        conf_name: Config file name without .conf extension.
        stanza: Stanza name within the config file.
        key: Key to look up inside the stanza.

    Returns:
        The trimmed string value, or None if not found/empty.
    """
    if service is None:
        raise RuntimeError("Splunk service has not been initialized.")

    try:
        stanza_obj = service.confs[conf_name][stanza]
    except KeyError:
        logger.info("Config stanza not found: [%s] %s", conf_name, stanza)
        return None
    except Exception:
        logger.exception("Unexpected error reading [%s] %s", conf_name, stanza)
        return None

    raw_value = stanza_obj.content.get(key)
    if raw_value is None:
        logger.info("Config key not found: [%s] %s.%s", conf_name, stanza, key)
        return None

    value = str(raw_value).strip()
    if not value:
        logger.info("Config key is empty: [%s] %s.%s", conf_name, stanza, key)
    return value or None


def read_conf_stanza(
    service: Any,
    conf_name: str,
    stanza: str,
) -> Dict[str, str]:
    """Read an entire stanza from a Splunk .conf file in one REST call.

    Returns all key-value pairs as a dict with trimmed, non-empty values.
    Returns an empty dict if the stanza does not exist.

    Args:
        service: An initialized splunklib.client.Service.
        conf_name: Config file name without .conf extension.
        stanza: Stanza name within the config file.
    """
    if service is None:
        raise RuntimeError("Splunk service has not been initialized.")

    try:
        stanza_obj = service.confs[conf_name][stanza]
    except KeyError:
        logger.info("Config stanza not found: [%s] %s", conf_name, stanza)
        return {}
    except Exception:
        logger.exception("Unexpected error reading [%s] %s", conf_name, stanza)
        return {}

    result: Dict[str, str] = {}
    for key, raw_value in stanza_obj.content.items():
        if raw_value is None:
            continue
        value = str(raw_value).strip()
        if value:
            result[key] = value

    logger.info("Read stanza [%s] %s: %d keys", conf_name, stanza, len(result))
    return result


# ---------------------------------------------------------------------------
# Value parsers — convert raw conf strings to typed Python values
# ---------------------------------------------------------------------------


def parse_bool(val: Optional[str], default: bool = False) -> bool:
    """Convert a configuration string to boolean.

    Recognises common truthy/falsy representations used in Splunk .conf files.
    Returns *default* for None or unrecognised values.
    """
    if val is None:
        return default
    normalized = str(val).strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    logger.warning("Unrecognized boolean value '%s', using default %s", val, default)
    return default


def parse_csv_to_set(raw: Optional[str]) -> Set[str]:
    """Split a comma-separated string into a set of trimmed, non-empty values."""
    if raw is None:
        return set()
    return {part.strip() for part in str(raw).split(",") if part.strip()}


def parse_json_dict(raw: Optional[str]) -> Dict[str, str]:
    """Parse a JSON string as a dict, normalising keys and values.

    Keys are stripped and trailing slashes removed. Empty keys/values are dropped.
    Returns an empty dict on parse failure.
    """
    if raw is None:
        return {}
    value = str(raw).strip()
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except Exception as e:
        logger.warning("Invalid JSON dictionary value '%s': %s", raw, e)
        return {}
    if not isinstance(parsed, dict):
        logger.warning("Expected JSON dictionary but got: %s", type(parsed).__name__)
        return {}
    return {
        str(k).strip().rstrip("/"): str(v).strip()
        for k, v in parsed.items()
        if str(k).strip() and str(v).strip()
    }


# ---------------------------------------------------------------------------
# Typed setters — apply a conf value to a dataclass attribute with validation
# ---------------------------------------------------------------------------


def set_conf_float(
    instance: Any,
    conf: Dict[str, str],
    key: str,
    attr: str,
    min_val: Optional[float] = None,
) -> None:
    """Set a float attribute from conf, clamping to min_val if provided."""
    raw = conf.get(key)
    if raw is None:
        return
    try:
        val = float(raw)
        if min_val is not None and val < min_val:
            logger.warning("%s cannot be below %s; clamping", key, min_val)
            val = min_val
        setattr(instance, attr, val)
    except ValueError as e:
        logger.warning("Invalid %s, keeping default: %s", key, e)


def set_conf_int(
    instance: Any,
    conf: Dict[str, str],
    key: str,
    attr: str,
    min_val: Optional[int] = None,
    positive: bool = False,
) -> None:
    """Set an int attribute from conf, with optional min_val and positive constraints."""
    raw = conf.get(key)
    if raw is None:
        return
    try:
        val = int(raw)
        if positive and val <= 0:
            logger.warning("%s must be positive; keeping default", key)
            return
        if min_val is not None and val < min_val:
            logger.warning("%s cannot be below %s; clamping", key, min_val)
            val = min_val
        setattr(instance, attr, val)
    except ValueError as e:
        logger.warning("Invalid %s, keeping default: %s", key, e)


def set_conf_bool(
    instance: Any,
    conf: Dict[str, str],
    key: str,
    attr: str,
    default: bool = True,
) -> None:
    """Set a boolean attribute from conf using parse_bool."""
    raw = conf.get(key)
    if raw is not None:
        setattr(instance, attr, parse_bool(raw, default=default))


# ---------------------------------------------------------------------------
# Static JSON file loaders — load bundled app configuration
# ---------------------------------------------------------------------------


def load_safe_spl_config() -> Tuple[Set[str], Set[str], Dict[str, Any]]:
    """Load safe SPL commands, exclusions, and sub-search config from safe_spl.json.

    Returns:
        Tuple of (safe_spl_commands, exclude_tools, sub_search_arg_cmd).
    """
    data = load_app_json("safe_spl.json")
    if data is None:
        logger.warning("No safe SPL configuration found; using empty defaults")
        return set(), set(), {}
    commands = set(data.get("safe_spl_commands", []))
    exclude_tools = set(data.get("exclude_tools", []))
    sub_search_arg_cmd = data.get("sub_search_arg_cmd", {})
    logger.info(
        "Loaded %d safe SPL commands, %d exclusions", len(commands), len(exclude_tools)
    )
    return commands, exclude_tools, sub_search_arg_cmd


def load_generating_commands() -> Set[str]:
    """Load SPL generating commands from generating_commands.json."""
    data = load_app_json("generating_commands.json")
    if data is None:
        return set()
    commands = set(data.get("generating_commands", []))
    logger.info("Loaded %d generating commands", len(commands))
    return commands


# ---------------------------------------------------------------------------
# File helpers — locate and load files from the app's local/default dirs
# ---------------------------------------------------------------------------


def find_app_file(filename: str) -> Optional[Path]:
    """Find a file in the app's local/ or default/ directory (local takes precedence)."""
    app_path = Path(__file__).parent.parent
    for subdir in ("local", "default"):
        path = app_path / subdir / filename
        if path.exists():
            return path
    return None


def load_app_json(filename: str) -> Optional[dict]:
    """Load and parse a JSON file from the app's local/ or default/ directory.

    Returns None if file not found or parse fails.
    """
    path = find_app_file(filename)
    if path is None:
        logger.warning("File '%s' not found in app directories", filename)
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load %s: %s", path, e)
        return None


# ---------------------------------------------------------------------------
# Conf appliers — populate a config instance from Splunk REST API data
# ---------------------------------------------------------------------------


def load_conf_into(instance: Any, service: Any) -> None:
    """Load Splunk .conf values into an MCPSettings instance.

    Reads mcp.conf [server] and app.conf via the Splunk REST API
    (``service.confs[...]``) and sets the corresponding fields on
    *instance* (the MCPSettings singleton).  Each field uses a typed
    setter that validates, clamps, and logs the value.

    :param instance: The MCPSettings singleton to populate.
    :param service: A ``splunklib.client.Service``
    """
    conf = read_conf_stanza(service, CONF_MCP, STANZA_SERVER)

    # Server settings
    set_conf_float(instance, conf, CONF_KEY_TIMEOUT, CONF_KEY_TIMEOUT)
    set_conf_int(instance, conf, CONF_KEY_MAX_ROW_LIMIT, CONF_KEY_MAX_ROW_LIMIT)
    set_conf_int(instance, conf, CONF_KEY_DEFAULT_ROW_LIMIT, CONF_KEY_DEFAULT_ROW_LIMIT)
    set_conf_bool(
        instance,
        conf,
        CONF_KEY_REQUIRE_ENCRYPTED_TOKEN,
        CONF_KEY_REQUIRE_ENCRYPTED_TOKEN,
    )
    set_conf_int(
        instance,
        conf,
        CONF_KEY_LEGACY_TOKEN_GRACE_DAYS,
        CONF_KEY_LEGACY_TOKEN_GRACE_DAYS,
        min_val=0,
    )
    set_conf_float(
        instance,
        conf,
        CONF_KEY_TOKEN_KEY_RELOAD_INTERVAL,
        CONF_KEY_TOKEN_KEY_RELOAD_INTERVAL,
        min_val=0.0,
    )

    # Token lifetime settings (with max >= default constraint)
    set_conf_int(
        instance,
        conf,
        CONF_KEY_MCP_TOKEN_MAX_LIFETIME,
        CONF_KEY_MCP_TOKEN_MAX_LIFETIME,
        positive=True,
    )
    set_conf_int(
        instance,
        conf,
        CONF_KEY_MCP_TOKEN_DEFAULT_LIFETIME,
        CONF_KEY_MCP_TOKEN_DEFAULT_LIFETIME,
        positive=True,
    )

    if (
        instance.mcp_token_default_lifetime_seconds
        > instance.mcp_token_max_lifetime_seconds
    ):
        logger.warning("%s exceeds max; clamping", CONF_KEY_MCP_TOKEN_DEFAULT_LIFETIME)
        instance.mcp_token_default_lifetime_seconds = (
            instance.mcp_token_max_lifetime_seconds
        )

    # CUI (Common User Interface) JWT validation settings
    set_conf_bool(
        instance,
        conf,
        CONF_KEY_CUI_ENFORCE_JWT_VALIDATION,
        CONF_KEY_CUI_ENFORCE_JWT_VALIDATION,
    )
    load_cui_settings(instance, conf)
    set_conf_int(
        instance,
        conf,
        CONF_KEY_CUI_JWT_CLOCK_SKEW,
        CONF_KEY_CUI_JWT_CLOCK_SKEW,
        min_val=0,
    )

    # App metadata
    load_app_metadata(instance, service)


def load_cui_settings(instance: Any, conf: Dict[str, str]) -> None:
    """Load CUI JWT issuer/audience/algorithm settings from conf."""
    raw = conf.get(CONF_KEY_CUI_ALLOWED_ISSUERS)
    if raw is not None:
        instance.cui_allowed_issuers = {
            issuer.rstrip("/") for issuer in parse_csv_to_set(raw)
        }

    raw = conf.get(CONF_KEY_CUI_ALLOWED_AUDIENCES)
    if raw is not None:
        instance.cui_allowed_audiences = parse_csv_to_set(raw)

    raw = conf.get(CONF_KEY_CUI_ALLOWED_JWT_ALGS)
    if raw is not None:
        algs = {alg.upper() for alg in parse_csv_to_set(raw)}
        instance.cui_allowed_jwt_algs = algs if algs else {"RS256"}

    raw = conf.get(CONF_KEY_CUI_JWKS_BY_ISSUER)
    if raw is not None:
        instance.cui_jwks_by_issuer = parse_json_dict(raw)


def load_app_metadata(instance: Any, service: Any) -> None:
    """Load app name/version from app.conf via REST API."""
    id_stanza = read_conf_stanza(service, CONF_APP, STANZA_ID)
    launcher_stanza = read_conf_stanza(service, CONF_APP, STANZA_LAUNCHER)

    name = id_stanza.get(CONF_KEY_NAME)
    if not name:
        package_stanza = read_conf_stanza(service, CONF_APP, STANZA_PACKAGE)
        name = package_stanza.get(CONF_KEY_ID)
    if not name:
        name = launcher_stanza.get(CONF_KEY_TITLE)
    if name:
        instance.app_name = name

    version = id_stanza.get(CONF_KEY_VERSION) or launcher_stanza.get(CONF_KEY_VERSION)
    if version:
        instance.app_version = version

    logger.info("App metadata: %s v%s", instance.app_name, instance.app_version)
