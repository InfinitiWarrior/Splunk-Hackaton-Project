"""
Splunk API Client Module.

This module provides a comprehensive interface for interacting with Splunk's REST API,
including SPL query execution, safety validation, and response processing. It handles
authentication, error management, and data format conversion for MCP integration.
"""

from __future__ import annotations

import http
import json
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, urljoin

import requests
import urllib3
from constants import (
    ACL,
    APP,
    AUTHORIZATION_HEADER_NAME,
    CONTENT,
    DISABLED,
    ENTRY,
    ERROR,
    MESSAGES,
    TEXT,
    TRACEPARENT_HEADER_NAME,
    TYPE,
)
from logging_config import get_logger, get_traceparent
from requests import Response
from settings import MCPSettings

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Module logger
logger = get_logger(__name__)

_ERROR_MESSAGE_TYPES = frozenset({"ERROR", "FATAL", "WARN"})


def normalize_search_command(spl: str, max_row_limit: Optional[int] = None) -> str:
    """
    Normalize SPL search command to ensure proper format and add row limit.

    This function standardizes SPL queries by ensuring they start with appropriate
    search commands and adds row limiting to prevent excessive resource usage.

    Args:
        spl: The SPL query string to normalize.
        max_row_limit: Maximum number of rows to return. If None, uses settings.

    Returns:
        Normalized SPL query string with head limit applied.
    """
    if max_row_limit is None:
        settings = MCPSettings.get()
        max_row_limit = settings.max_row_limit

    # Remove leading/trailing whitespace
    spl = spl.strip()
    if not spl:
        logger.warning("Empty SPL query provided")
        return ""

    logger.info("Normalizing SPL query")

    # Check if already starts with 'search' or pipe
    if spl.lower().startswith("search ") or spl.startswith("|"):
        normalized = f"{spl} | head {max_row_limit + 1}"
        logger.info("Query already properly formatted, added head limit")
        return normalized

    # Tokenize to get first meaningful word
    tokens = spl.split(maxsplit=1)
    if not tokens:
        return ""

    first_word = tokens[0].lower()

    # Get generating commands from settings
    settings = MCPSettings.get()
    if first_word in settings.generating_commands:
        normalized = f"{spl} | head {max_row_limit + 1}"
        logger.info("Query starts with generating command, added head limit")
        return normalized

    # Otherwise, prepend 'search' and add head limit
    normalized = f"search {spl} | head {max_row_limit + 1}"
    logger.info("Prepended 'search' and added head limit")
    return normalized


def check_spl_safe(
    settings: MCPSettings, session_key: str, spl_query: str
) -> Tuple[bool, str]:
    """
    Validate that a Splunk query is safe to execute, including recursive subsearch validation.

    This function uses Splunk's parser API to analyze the query structure
    and ensures all commands are in the allowed safe commands list.

    Args:
        settings: MCPSettings instance containing configuration.
        session_key: Splunk session key for authentication.
        spl_query: The Splunk query to validate.

    Returns:
        Tuple containing:
            - bool: True if query is safe, False otherwise
            - str: Status message or error description
    """
    logger.info("Validating SPL query safety")

    try:
        # Parse the query using Splunk API
        response = call_splunk_api(
            session_key=session_key,
            method="POST",
            api="services/search/parser",
            data={
                "q": spl_query,
                "expand_macros": "0",
                "output_mode": "json",
                "parse_only": "1",
            },
        )

        if response.status_code != 200:
            logger.error(
                "Parser API returned error %d: %s", response.status_code, response.text
            )
            return False, f"Error parsing Splunk query: {response.text}"

        # Parse the response
        query_tree = response.json()
        parsed_commands = query_tree.get("commands", [])

        # Check each command against safe list
        for cmd in parsed_commands:
            cmd_name = cmd.get("command", "").strip().lower()
            if cmd_name and cmd_name not in settings.safe_spl_commands:
                logger.warning("Forbidden command detected: %s", cmd_name)
                return False, f"Forbidden command found: {cmd_name}"

            # Recursively check subsearches if defined
            if cmd_name in settings.sub_search_arg_cmd:
                subsearch_args = settings.sub_search_arg_cmd[cmd_name]
                cmd_args = cmd.get("args", {})

                for arg_name in subsearch_args:
                    if arg_name == "args":
                        raw_args = cmd.get("rawargs", "")
                        if raw_args:
                            subsearch_matches = re.findall(r"\[([^]]+)]", raw_args)
                            for subsearch in subsearch_matches:
                                is_safe, message = check_spl_safe(
                                    settings, session_key, subsearch.strip()
                                )
                                if not is_safe:
                                    return (
                                        False,
                                        f"Unsafe subsearch in {cmd_name}: {message}",
                                    )
                    else:
                        values_to_check: List[str] = []
                        if isinstance(cmd_args, dict):
                            if arg_name in cmd_args:
                                arg_value = cmd_args[arg_name]
                                if isinstance(arg_value, str):
                                    values_to_check.append(arg_value)
                        elif isinstance(cmd_args, list):
                            for item in cmd_args:
                                if isinstance(item, dict) and arg_name in item:
                                    item_value = item[arg_name]
                                    if isinstance(item_value, str):
                                        values_to_check.append(item_value)
                                elif isinstance(item, str):
                                    values_to_check.append(item)
                        elif isinstance(cmd_args, str):
                            values_to_check.append(cmd_args)

                        for value in values_to_check:
                            start = 0
                            while True:
                                open_idx = value.find("[", start)
                                if open_idx == -1:
                                    break
                                close_idx = value.find("]", open_idx + 1)
                                if close_idx == -1:
                                    break
                                subsearch = value[open_idx + 1 : close_idx].strip()
                                if subsearch:
                                    is_safe, message = check_spl_safe(
                                        settings, session_key, subsearch
                                    )
                                    if not is_safe:
                                        return (
                                            False,
                                            f"Unsafe subsearch in {cmd_name} {arg_name}: {message}",
                                        )
                                start = close_idx + 1

        logger.info("SPL query validation passed")
        return True, "Query is safe to run."

    except (json.JSONDecodeError, KeyError) as e:
        logger.error("Failed to parse query validation response: %s", e)
        return False, f"Error parsing Splunk query response: {e}"
    except Exception as e:
        logger.exception("Unexpected error during SPL validation: %s", e)
        return False, f"Validation error: {e}"


@dataclass
class NdjsonParseResult:
    """Parsed output from Splunk's NDJSON export stream.

    Attributes:
        results: Extracted search result objects.
        errors: ERROR/FATAL/WARN messages found in the stream (e.g. from
            ``| rest`` failures that Splunk reports inline instead of via
            HTTP status).
    """

    results: List[Any] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def convert_ndjson_to_dict(ndjson: str) -> NdjsonParseResult:
    """
    Convert NDJSON (Newline Delimited JSON) string to structured data.

    This function processes Splunk's NDJSON export format, extracting result
    objects and filtering out metadata fields like preview, offset, and lastrow.
    It also captures ERROR and FATAL messages that Splunk embeds in the stream
    when commands like ``| rest`` encounter upstream failures.

    Args:
        ndjson: The NDJSON string to convert.

    Returns:
        NdjsonParseResult with extracted results and any error messages.
    """
    logger.info("Converting NDJSON response to structured data")

    valid_results: List[Any] = []
    errors: List[str] = []
    lines_processed = 0

    for line in ndjson.splitlines():
        line = line.strip()
        if not line:
            continue

        lines_processed += 1

        try:
            json_obj = json.loads(line)
            if not isinstance(json_obj, dict):
                continue

            # Capture ERROR/FATAL/WARN messages embedded within the messages field
            # in the export endpoint response.
            if MESSAGES in json_obj:
                for msg in json_obj[MESSAGES]:
                    if isinstance(msg, dict) and msg.get(TYPE) in _ERROR_MESSAGE_TYPES:
                        errors.append(msg[TEXT])

            # Extract result
            if "result" in json_obj:
                result_data = json_obj["result"]
            else:
                result_data = {}

            # If result_data is a dict remove metadata fields
            if isinstance(result_data, dict):
                # Remove Splunk metadata fields
                metadata_fields = ["preview", "offset", "lastrow"]
                for md_field in metadata_fields:
                    result_data.pop(md_field, None)

            # Only include non-empty results
            if result_data:
                valid_results.append(result_data)

        except json.JSONDecodeError as e:
            logger.warning("Failed to parse NDJSON line %d: %s", lines_processed, e)
            continue

    if errors:
        logger.error(
            "NDJSON stream contained %d error message(s): %s",
            len(errors),
            "; ".join(errors),
        )

    return NdjsonParseResult(results=valid_results, errors=errors)


def _build_error_response(status: int, detail: str) -> Response:
    """
    Create a synthetic Response object for error conditions.

    This helper function creates a properly formatted Response object
    for cases where network requests fail or timeout.

    Args:
        status: HTTP status code.
        detail: Error description.

    Returns:
        Response object with error information.
    """
    response = Response()
    response.status_code = status
    response._content = json.dumps({"detail": detail}).encode("utf-8")
    response.headers["Content-Type"] = "application/json"

    logger.info("Created error response: %d - %s", status, detail)
    return response


def call_splunk_api(
    session_key: str,
    method: str,
    api: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Union[Dict, str, bytes, None] = None,
) -> Response:
    """
    Make authenticated HTTP requests to Splunk's REST API.

    This function handles all aspects of Splunk API communication including
    authentication, request formatting, timeout handling, and error management.

    Args:
        session_key: Splunk session key for authentication.
        method: HTTP method (GET, POST, etc.).
        api: API endpoint path relative to splunkd_url.
        headers: Optional additional headers.
        params: Optional query parameters.
        data: Optional request body data.

    Returns:
        Response object from the API call.
    """
    settings = MCPSettings.get()
    url = urljoin(settings.splunkd_url, api)

    logger.info("Splunk API call: %s %s", method.upper(), url)

    # Build request headers
    req_headers: Dict[str, str] = {
        "User-Agent": f"{settings.app_name}/{settings.app_version}",
        "Accept": "application/json",
    }

    # Add authentication if not already present
    if session_key and AUTHORIZATION_HEADER_NAME not in (headers or {}):
        req_headers[AUTHORIZATION_HEADER_NAME] = f"Bearer {session_key}"

    # Propagate traceparent from request context if available
    traceparent = get_traceparent()
    if traceparent:
        req_headers[TRACEPARENT_HEADER_NAME] = traceparent
        logger.info("Propagating traceparent to %s", url)

    # Merge additional headers
    if headers:
        req_headers.update(headers)

    try:
        # TLS verification is disabled because this is a localhost call to
        # splunkd, which uses a self-signed certificate by default. The
        # connection never leaves the machine, so there is no MITM risk.

        # nosemgrep: tools.semgrep.rules.CCF.disabled-cert-validation
        response = requests.request(method=method.upper(), url=url, headers=req_headers, params=params, data=data, timeout=settings.timeout, verify=False)  # fmt: skip

        logger.info(
            "API call completed with status %d for %s", response.status_code, url
        )
        return response

    except requests.Timeout as e:
        logger.error("Splunk API call timed out after %ds: %s", settings.timeout, e)
        return _build_error_response(
            int(http.HTTPStatus.GATEWAY_TIMEOUT), "Splunk API call timed out"
        )
    except requests.RequestException as e:
        logger.error("Splunk API request failed: %s", e)
        return _build_error_response(
            int(http.HTTPStatus.INTERNAL_SERVER_ERROR),
            f"Splunk API request failed: {e}",
        )


_SAFE_APP_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")


def _build_app_endpoint(
    base: str, app_name: Optional[str] = None, object_name: str = ""
) -> str:
    """Build a Splunk REST path scoped to an app namespace.

    Args:
        base: Resource path (e.g. ``"search/jobs/export"``,
              ``"saved/searches"``).
        app_name: App namespace. Scopes to that app when provided.
            Use ``"-"`` to target all apps.
        object_name: URL-encoded name of a specific object to address
            (e.g. a saved search name).
    """
    if app_name:
        path = f"servicesNS/-/{app_name}/{base}"
    else:
        path = f"services/{base}"
    if object_name:
        path = f"{path}/{object_name}"
    return path


def run_splunk_query_internal(
    settings: MCPSettings,
    session_key: str,
    query: str,
    earliest_time: Optional[str] = None,
    latest_time: Optional[str] = None,
    row_limit: int = 100,
    app: Optional[str] = None,
    tool_name: str = "",
) -> Dict[str, Any]:
    """
    Execute an SPL query against Splunk's export search endpoint.

    This function provides direct query execution with automatic query normalization
    and result formatting. It is intended for internal use by trusted components
    and does NOT perform safety validation - callers must validate queries first.

    The ``preview`` parameter is explicitly set to False when calling Splunk's
    export endpoint. Splunk defaults preview to True, which streams intermediate
    result snapshots during query execution. This causes two problems:

    1. Performance: Preview snapshots add processing overhead and increase response time.
    2. Correctness: All snapshots are returned as separate NDJSON lines. A query like
       ``stats count`` that should return 1 row may return multiple rows (intermediate
       previews plus the final result).

    Security Note:
        This function performs NO safety validation beyond adding row limits.
        Callers accepting untrusted input MUST validate SPL queries using
        check_spl_safe() before calling this function.

    Args:
        settings: MCPSettings containing API configuration.
        session_key: Splunk session key for authentication.
        query: Raw SPL query (will be normalized and limited).
        earliest_time: Search time window start (Splunk format).
        latest_time: Search time window end (Splunk format).
        row_limit: Number of results to return.
        app: Optional Splunk app namespace to scope the search job.
        tool_name: MCP tool name included in the provenance field for _audit
            tracking (e.g. ``MCP:Splunk_MCP_Server:splunk_get_info``).

    Returns:
        Dictionary containing either:
            - {"results": [<event_dict>, ...], "truncated": bool, "total_rows": int} on success
            - {"results": [<event_dict>, ...], "truncated": bool, "approx_total": str} when truncated
            - {"error": str} on failure
    """

    logger.info(
        "Executing SPL query: %s (app=%s)",
        query,
        app or "global",
    )

    # Submit query to export endpoint.
    # Note: The HTTP timeout (settings.timeout) applies to the connection and
    # time waiting for the first response bytes, not total query execution time.
    # Splunk's export endpoint streams results, so long-running queries will
    # continue as long as splunkd starts returning data within the timeout window.
    data = {
        "search": query,
        "output_mode": "json",
        "preview": False,
        "provenance": f"MCP:{settings.app_name}:{tool_name}",  # this helps tracks MCP initiated searches in _audit index for spl execution-type tools
    }
    if earliest_time is not None:
        data["earliest_time"] = earliest_time
    if latest_time is not None:
        data["latest_time"] = latest_time

    response = call_splunk_api(
        session_key=session_key,
        method="POST",
        api=_build_app_endpoint("search/jobs/export", app),
        data=data,
    )

    if response.status_code != 200:
        logger.error("Query execution failed with status %d", response.status_code)
        return {ERROR: response.text}

    logger.info("Query completed, parsing results")

    # Convert NDJSON response to structured data
    parsed = convert_ndjson_to_dict(response.text)

    # Return error back to the caller incase there are errors with no results.
    if parsed.errors and not parsed.results:
        error_text = "\n".join(parsed.errors)
        logger.error("Search produced no results and returned errors: %s", error_text)
        return {ERROR: error_text}

    results = parsed.results
    truncated = len(results) > row_limit
    result_out: Dict[str, Any] = {
        "results": results[:row_limit],
        "truncated": truncated,
    }

    # Add count information - use consistent integer types where possible
    if len(results) == settings.max_row_limit + 1:
        # When we hit the server limit, we can't know the exact total
        result_out["approx_total"] = f"{settings.max_row_limit}+"
    else:
        # We have the exact count
        result_out["total_rows"] = len(results)

    return result_out


def ttl_cache(ttl_seconds=60):
    def decorator(fn):
        cached_fn = lru_cache(maxsize=None)(fn)
        cached_fn.expiration = 0

        def wrapped(*args, **kwargs):
            if time.time() > cached_fn.expiration:
                cached_fn.cache_clear()
                cached_fn.expiration = time.time() + ttl_seconds
            return cached_fn(*args, **kwargs)

        return wrapped

    return decorator


@ttl_cache(ttl_seconds=60)
def get_installed_apps(
    session_key: str,
) -> Dict[str, Any]:
    """
    Get a list of enabled Splunk application names.

    This function retrieves all locally installed and enabled applications from Splunk using
    the REST API endpoint /services/apps/local. It returns only the names of enabled apps.

    Args:
        settings: MCPSettings containing API configuration.
        session_key: Splunk session key for authentication.

    Returns:
        Dictionary containing either:
            - {"apps": [<app_name_string>, ...]} on success
            - {"error": str, "status_code": int} on failure
    """
    logger.info("Retrieving enabled Splunk application names")

    try:
        # Call the Splunk REST API to get installed apps
        response = call_splunk_api(
            session_key=session_key,
            method="GET",
            api="services/apps/local",
            params={"count": "0", "output_mode": "json"},  # Get all apps
        )

        if response.status_code != 200:
            logger.error(
                "Apps API returned error %d: %s", response.status_code, response.text
            )
            return {
                "error": f"Failed to retrieve apps: {response.text}",
                "status_code": response.status_code,
            }

        # Parse the response
        apps_data = response.json()
        enabled_app_names = []

        entries = apps_data.get(ENTRY, [])

        for entry in entries:
            content = entry.get(CONTENT, {})
            if not content.get(DISABLED, False):
                app_name = entry.get("name", "")
                if app_name:
                    enabled_app_names.append(app_name)

        logger.info(
            "Successfully retrieved %d enabled applications", len(enabled_app_names)
        )
        return {"apps": enabled_app_names}

    except json.JSONDecodeError as e:
        logger.error("Failed to parse apps API response: %s", e)
        return {"error": f"Error parsing apps response: {e}", "status_code": 500}
    except Exception as e:
        logger.exception("Unexpected error retrieving apps: %s", e)
        return {"error": f"Unexpected error: {e}", "status_code": 500}


def is_saved_search_disabled(
    session_key: str, saved_search_name: str, app: Optional[str] = None
) -> Tuple[bool, str, Optional[str]]:
    """Check whether a Splunk saved search has disabled=1.

    Queries the ``/services/saved/searches`` REST endpoint and inspects
    the ``disabled`` property.  Defaults to ``0`` (enabled); when ``1``
    the saved search is not visible in Splunk Web.

    Args:
        session_key: Splunk session key for authentication.
        saved_search_name: Name of the saved search to check.
        app: Optional Splunk app namespace to scope the lookup.

    Returns:
        (is_disabled, message, resolved_app) where resolved_app is the
        Splunk app the saved search belongs to (None on lookup failure).
    """
    logger.info(
        "Checking disabled status for saved search '%s' (app=%s)",
        saved_search_name,
        app or "all",
    )
    not_found_msg = (
        f"Saved search '{saved_search_name}' not found. "
        "Use get_knowledge_objects with type='saved_searches' "
        "to list available saved searches."
    )

    encoded_name = quote(saved_search_name, safe="")
    if app is not None and not _SAFE_APP_RE.match(app):
        return False, f"Invalid app name: {app}", None
    response = call_splunk_api(
        session_key=session_key,
        method="GET",
        api=_build_app_endpoint("saved/searches", app or "-", object_name=encoded_name),
        params={"output_mode": "json"},
    )

    if response.status_code != http.HTTPStatus.OK:
        logger.error(
            "Saved searches API returned %d: %s",
            response.status_code,
            response.text,
        )
        if app and response.status_code in (
            http.HTTPStatus.FORBIDDEN,
            http.HTTPStatus.NOT_FOUND,
        ):
            return (
                False,
                f"Saved search '{saved_search_name}' not found in app '{app}'. "
                "Verify the app name and saved search name are correct, "
                "or omit the app parameter to search across all apps.",
                None,
            )
        if not app and response.status_code == http.HTTPStatus.NOT_FOUND:
            return False, not_found_msg, None
        return (
            False,
            f"Failed to check saved search status (HTTP {response.status_code}).",
            None,
        )

    try:
        entries = response.json()[ENTRY]
    except (json.JSONDecodeError, KeyError) as e:
        logger.error("Failed to parse saved search response: %s", e)
        return False, f"Error checking saved search status: {e}", None

    if not entries:
        return False, not_found_msg, None

    # When no app is specified the all-app lookup may return the same saved
    # search from multiple apps. Sort alphabetically by app name and pick the first entry.
    if app is None and len(entries) > 1:
        entries.sort(key=lambda e: e.get(ACL, {}).get(APP, ""))
        logger.info(
            "Saved search '%s' exists in multiple apps %s; using '%s'",
            saved_search_name,
            [e.get(ACL, {}).get(APP) for e in entries],
            entries[0].get(ACL, {}).get(APP),
        )

    entry = entries[0]
    resolved_app = entry.get(ACL, {}).get(APP)

    try:
        content = entry[CONTENT]
    except KeyError as e:
        logger.error("Failed to parse saved search entry: %s", e)
        return False, f"Error checking saved search status: {e}", None
    logger.info(
        "Saved search '%s' resolved to app '%s'",
        saved_search_name,
        resolved_app or "unknown",
    )

    disabled = content.get(DISABLED, False)
    if disabled is True or disabled == "1":
        logger.warning("Saved search '%s' is disabled", saved_search_name)
        return (
            True,
            f"Saved search '{saved_search_name}' is disabled and cannot be executed.",
            resolved_app,
        )

    logger.info("Saved search '%s' is enabled", saved_search_name)
    return False, "Saved search is enabled.", resolved_app


# Public API exports
__all__ = [
    "NdjsonParseResult",
    "normalize_search_command",
    "check_spl_safe",
    "convert_ndjson_to_dict",
    "call_splunk_api",
    "run_splunk_query_internal",
    "get_installed_apps",
    "is_saved_search_disabled",
]
