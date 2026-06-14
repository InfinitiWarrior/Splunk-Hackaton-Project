"""
MCP Tools REST Handler.

Provides CRUD-style endpoints for managing MCP tool definitions. This module
currently implements the POST method which validates incoming tool payloads
and persists them to the `mcp_tools` KV Store collection. Additional methods
will be implemented in future iterations.
"""

from __future__ import annotations

import json
import os
import re
import sys
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from splunk.persistconn.application import PersistentServerConnectionApplication

_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

import http

import mcp_tools_batch_contracts as batch_contracts
from constants import EVENT_TOOL_DISABLED, EVENT_TOOL_ENABLED
from kvstore_manager import KVStoreManager
from logging_config import (
    clear_log_context,
    get_logger,
    log_telemetry,
    update_log_context,
    update_log_context_req_id,
)
from settings import MCPSettings
from splunk_api import get_installed_apps
from tool_enabled_collection import ToolCollectionError
from tool_manager import get_default_manager

logger = get_logger(__name__)

Response = Tuple[int, Dict[str, Any]]

_ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE"}
_ALLOWED_API_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_ALLOWED_ARGUMENT_TYPES = {"string", "integer", "number", "boolean"}

_FIELD_TITLE = "title"
_FIELD_SAVED_SEARCH = "saved_search"


class ToolValidationError(ValueError):
    """Raised when an incoming tool definition fails validation."""

    def __init__(self, errors: List[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


class BatchReplaceToolsService:
    """Encapsulates app-scoped batch tool replacement."""

    def __init__(
        self,
        handler: "MCPToolsRestHandler",
        session_key: str,
        request: Dict[str, Any],
    ) -> None:
        self.handler = handler
        self.session_key = session_key
        self.request = request

    def execute(self, payload: Dict[str, Any]) -> Response:
        """Run the full batch replace lifecycle.

        Phases:
            1. Parse and validate the incoming payload contract.
            2. Normalize each tool definition and check for duplicates.
            3. Query KV Store for existing tools and compute the diff.
            4. Upsert tools (insert new / replace existing); rollback on failure.
            5. Remove stale tools, clean up enabled entries, refresh cache.
        """
        # Phase 1: Parse and validate the incoming payload contract.
        contract, contract_error = batch_contracts.BatchReplaceRequest.from_payload(
            payload
        )
        if contract_error:
            return contract_error

        if contract is None:  # pragma: no cover - defensive
            return batch_contracts.invalid_tools_response()
        external_app_id = contract.external_app_id
        tools = contract.tools

        logger.info(
            f"Starting batch replace for app '{external_app_id}' with {len(tools)} tools."
        )

        # Phase 2: Normalize each tool definition and check for duplicates.
        normalized_tools, validation_errors = self._normalize_tools(
            tools, external_app_id
        )
        if validation_errors:
            logger.warning(
                f"Batch replace validation failed for app '{external_app_id}' with {len(validation_errors)} errors: {validation_errors}"
            )
            return batch_contracts.validation_error_response(validation_errors)

        duplicate_tool_ids = self._find_duplicate_tool_ids(normalized_tools)
        if duplicate_tool_ids:
            logger.warning(
                f"Batch replace payload contains duplicate tool ids for app '{external_app_id}': {sorted(set(duplicate_tool_ids))}"
            )
            return batch_contracts.duplicate_tools_response(duplicate_tool_ids)

        # Phase 3: Query KV Store for existing tools and compute the
        # diff (stale keys to delete, existing keys to replace in-place).
        kv_manager = self.handler._create_kv_manager(self.session_key)
        existing_tools, query_error = self._query_existing_tools(
            kv_manager, external_app_id
        )
        if query_error:
            return query_error

        existing_app_tools, skipped_built_in = self._index_existing_app_tools(
            existing_tools, external_app_id
        )
        new_tool_keys = {t.get("_key") for t in normalized_tools if t.get("_key")}
        stale_keys = set(existing_app_tools.keys()) - new_tool_keys
        logger.info(
            f"Batch replace context for app '{external_app_id}': "
            f"normalized={len(normalized_tools)} existing={len(existing_app_tools)} "
            f"stale={len(stale_keys)} skipped_built_in={len(skipped_built_in)}"
        )

        # Phase 4: Upsert (insert new / replace existing) tool definitions.
        # On any failure, roll back all mutations and return early.
        (
            registered_tools,
            failed_inserts,
            inserted_tool_keys,
            replaced_original_docs,
        ) = self._upsert_tools(kv_manager, normalized_tools, existing_app_tools)

        if failed_inserts:
            logger.error(
                f"Batch replace upsert failed for app '{external_app_id}': "
                f"registered={len(registered_tools)} failed_inserts={len(failed_inserts)}. Attempting rollback."
            )
            rollback_failures = self._rollback_upserts(
                kv_manager, inserted_tool_keys, replaced_original_docs
            )
            if rollback_failures:
                logger.warning(
                    f"Batch replace rollback incomplete for app '{external_app_id}': rollback_failures={len(rollback_failures)}"
                )
            else:
                logger.info(
                    f"Batch replace rollback succeeded for app '{external_app_id}'."
                )
            self._refresh_tool_cache(external_app_id, partial=True)
            return batch_contracts.upsert_failure_response(
                external_app_id=external_app_id,
                registered_count=len(registered_tools),
                failed_inserts=failed_inserts,
                rollback_failures=rollback_failures,
            )

        # Phase 5: Remove stale tools that are no longer in the new set,
        # clean up their enabled-state entries, and refresh the tool cache.
        deleted_tools, failed_deletes = self._delete_stale_tools(
            kv_manager, stale_keys, existing_app_tools
        )

        self.handler._cleanup_enabled_entries(
            self.handler._extract_tool_names(deleted_tools),
            self.session_key,
        )

        self.handler.tool_manager.invalidate_enabled_tool_cache()
        self._refresh_tool_cache(external_app_id, partial=False)
        logger.info(
            f"Batch replace stale cleanup for app '{external_app_id}': deleted={len(deleted_tools)} failed_deletes={len(failed_deletes)}"
        )

        if failed_deletes:
            logger.warning(
                f"Batch replace completed with stale delete failures for app '{external_app_id}'."
            )

        logger.info(
            f"Batch replace completed for app '{external_app_id}': "
            f"registered={len(registered_tools)} deleted={len(deleted_tools)} "
            f"skipped_built_in={len(skipped_built_in)} failed_deletes={len(failed_deletes)}"
        )

        return batch_contracts.success_response(
            external_app_id=external_app_id,
            registered_count=len(registered_tools),
            deleted_count=len(deleted_tools),
            skipped_built_in=skipped_built_in,
            failed_deletes=failed_deletes,
        )

    def _normalize_tools(
        self, tools: List[Any], external_app_id: str
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Validate and normalize each raw tool dict.

        Ensures every tool has a consistent ``_meta.external_app_id`` and passes
        through the handler's ``_normalize_tool_definition`` pipeline.

        Returns:
            (normalized_tools, validation_errors) — errors are human-readable strings.
        """
        normalized_tools: List[Dict[str, Any]] = []
        validation_errors: List[str] = []

        for index, raw_tool in enumerate(tools):
            if not isinstance(raw_tool, dict):
                validation_errors.append(
                    f"Tool at index {index} must be a JSON object."
                )
                continue

            tool_name = raw_tool.get("name", f"index {index}")
            tool_payload = deepcopy(raw_tool)
            meta = tool_payload.get("_meta")
            if meta is None:
                tool_payload["_meta"] = {"external_app_id": external_app_id}
            elif isinstance(meta, dict):
                incoming_external_app_id = meta.get("external_app_id")
                if (
                    isinstance(incoming_external_app_id, str)
                    and incoming_external_app_id.strip()
                    and incoming_external_app_id.strip() != external_app_id
                ):
                    validation_errors.append(
                        f"Tool '{tool_name}' (index {index}) has mismatched external_app_id "
                        f"'{incoming_external_app_id}'."
                    )
                    continue
                tool_payload["_meta"] = deepcopy(meta)
                tool_payload["_meta"]["external_app_id"] = external_app_id
            else:
                validation_errors.append(
                    f"Tool '{tool_name}' (index {index}) has invalid '_meta' field."
                )
                continue

            try:
                normalized_tools.append(
                    self.handler._normalize_tool_definition(tool_payload, self.request)
                )
            except ToolValidationError as exc:
                validation_errors.extend(
                    [
                        f"Tool '{tool_name}' (index {index}): {error}"
                        for error in exc.errors
                    ]
                )

        return normalized_tools, validation_errors

    def _find_duplicate_tool_ids(self, tools: List[Dict[str, Any]]) -> List[str]:
        """Return _key values that appear more than once in the normalized tool list."""
        seen_tool_ids = set()
        duplicate_tool_ids: List[str] = []
        for tool_doc in tools:
            tool_id = tool_doc.get("_key")
            if not isinstance(tool_id, str):
                continue
            if tool_id in seen_tool_ids:
                duplicate_tool_ids.append(tool_id)
            seen_tool_ids.add(tool_id)
        return duplicate_tool_ids

    def _query_existing_tools(
        self, kv_manager: KVStoreManager, external_app_id: str
    ) -> Tuple[Optional[List[Any]], Optional[Response]]:
        """Fetch all tool documents from KV Store.

        Returns:
            (tool_list, None) on success, or (None, error_response) on failure.
        """
        query_response = kv_manager.query(output_mode="json", count="0")
        if query_response.status_code != 200:
            logger.error(
                f"KV Store query failed for batch replace ({query_response.status_code}): {query_response.text}"
            )
            return None, batch_contracts.kv_query_failed_response(
                query_response.status_code,
                self.handler._safe_json(query_response),
            )

        try:
            existing_tools = query_response.json()
        except ValueError:
            logger.error(
                f"Failed to decode KV Store response for batch replace: {query_response.text}"
            )
            return None, batch_contracts.kv_malformed_data_response()

        if not isinstance(existing_tools, list):
            logger.error(
                f"KV Store query returned non-list payload for batch replace app '{external_app_id}': {type(existing_tools).__name__}"
            )
            return None, batch_contracts.kv_unexpected_data_response()

        return existing_tools, None

    def _index_existing_app_tools(
        self, existing_tools: List[Any], external_app_id: str
    ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, str]]]:
        """Partition existing tools for this app into mutable and built-in sets.

        Returns:
            (existing_app_tools_by_key, skipped_built_in) — built-in tools are
            never modified or deleted by batch replace.
        """
        existing_app_tools: Dict[str, Dict[str, Any]] = {}
        skipped_built_in: List[Dict[str, str]] = []

        for tool_doc in existing_tools:
            if not isinstance(tool_doc, dict):
                continue
            meta = tool_doc.get("_meta", {})
            if not isinstance(meta, dict):
                continue
            if meta.get("external_app_id") != external_app_id:
                continue
            tool_id = tool_doc.get("_key")
            if not isinstance(tool_id, str) or not tool_id:
                continue
            tool_name = tool_doc.get("name", tool_id)
            _, is_built_in = self.handler._extract_tool_meta_flags(tool_doc)
            if is_built_in:
                skipped_built_in.append({"tool_id": tool_id, "name": tool_name})
                continue
            existing_app_tools[tool_id] = tool_doc

        return existing_app_tools, skipped_built_in

    def _upsert_tools(
        self,
        kv_manager: KVStoreManager,
        normalized_tools: List[Dict[str, Any]],
        existing_app_tools: Dict[str, Dict[str, Any]],
    ) -> Tuple[
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        Dict[str, str],
        Dict[str, Dict[str, Any]],
    ]:
        """Insert or replace each tool in KV Store.

        Existing tools (matched by _key) are replaced in-place; new tools are
        inserted.  Tracks inserted keys and original docs for rollback.

        Returns:
            (registered, failed, inserted_keys, replaced_originals)
        """
        registered_tools: List[Dict[str, Any]] = []
        failed_inserts: List[Dict[str, Any]] = []
        inserted_tool_keys: Dict[str, str] = {}
        replaced_original_docs: Dict[str, Dict[str, Any]] = {}

        for tool_doc in normalized_tools:
            tool_id = tool_doc.get("_key")
            existing_doc = existing_app_tools.get(tool_id) if tool_id else None
            if tool_id and existing_doc:
                upsert_response = kv_manager.replace(tool_id, tool_doc)
            else:
                upsert_response = kv_manager.insert(tool_doc)

            if self.handler._is_kv_status(upsert_response, (200, 201)):
                registered_tools.append(
                    {"tool_id": tool_id, "name": tool_doc.get("name", tool_id)}
                )
                if tool_id and existing_doc:
                    replaced_original_docs[tool_id] = deepcopy(existing_doc)
                elif isinstance(tool_id, str) and tool_id:
                    inserted_tool_keys[tool_id] = tool_doc.get("name", tool_id)
            else:
                failed_inserts.append(
                    {
                        "tool_name": tool_doc.get("name"),
                        "tool_id": tool_id,
                        "error": self.handler._safe_json(upsert_response),
                    }
                )

        return (
            registered_tools,
            failed_inserts,
            inserted_tool_keys,
            replaced_original_docs,
        )

    def _rollback_upserts(
        self,
        kv_manager: KVStoreManager,
        inserted_tool_keys: Dict[str, str],
        replaced_original_docs: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Best-effort rollback: delete newly inserted keys and restore replaced docs.

        Returns:
            List of rollback operations that failed (empty on full success).
        """
        rollback_failures: List[Dict[str, Any]] = []

        for inserted_key in sorted(inserted_tool_keys):
            inserted_name = inserted_tool_keys[inserted_key]
            try:
                rollback_delete = kv_manager.delete(inserted_key)
            except Exception as exc:  # pragma: no cover - defensive
                rollback_failures.append(
                    {
                        "operation": "delete_inserted",
                        "tool_id": inserted_key,
                        "tool_name": inserted_name,
                        "error": str(exc),
                    }
                )
                continue

            if not self.handler._is_kv_status(rollback_delete, (200, 204, 404)):
                rollback_failures.append(
                    {
                        "operation": "delete_inserted",
                        "tool_id": inserted_key,
                        "tool_name": inserted_name,
                        "error": rollback_delete.text,
                    }
                )

        for replaced_key in sorted(replaced_original_docs):
            original_doc = replaced_original_docs[replaced_key]
            replaced_name = original_doc.get("name", replaced_key)
            try:
                rollback_replace = kv_manager.replace(replaced_key, original_doc)
            except Exception as exc:  # pragma: no cover - defensive
                rollback_failures.append(
                    {
                        "operation": "restore_replaced",
                        "tool_id": replaced_key,
                        "tool_name": replaced_name,
                        "error": str(exc),
                    }
                )
                continue

            if rollback_replace.status_code == 404:
                rollback_insert = kv_manager.insert(original_doc)
                if not self.handler._is_kv_status(rollback_insert, (200, 201)):
                    rollback_failures.append(
                        {
                            "operation": "restore_replaced",
                            "tool_id": replaced_key,
                            "tool_name": replaced_name,
                            "error": rollback_insert.text,
                        }
                    )
            elif not self.handler._is_kv_status(rollback_replace, (200, 201)):
                rollback_failures.append(
                    {
                        "operation": "restore_replaced",
                        "tool_id": replaced_key,
                        "tool_name": replaced_name,
                        "error": rollback_replace.text,
                    }
                )

        return rollback_failures

    def _delete_stale_tools(
        self,
        kv_manager: KVStoreManager,
        stale_keys: set,
        existing_app_tools: Dict[str, Dict[str, Any]],
    ) -> Tuple[List[Dict[str, str]], List[Dict[str, Any]]]:
        """Remove tools whose keys are no longer present in the new tool set.

        Returns:
            (deleted_tools, failed_deletes)
        """
        deleted_tools: List[Dict[str, str]] = []
        failed_deletes: List[Dict[str, Any]] = []

        for stale_key in sorted(stale_keys):
            stale_doc = existing_app_tools[stale_key]
            stale_name = stale_doc.get("name", stale_key)
            delete_response = kv_manager.delete(stale_key)
            if self.handler._is_kv_status(delete_response, (200, 204)):
                deleted_tools.append({"tool_id": stale_key, "name": stale_name})
            else:
                failed_deletes.append(
                    {
                        "tool_id": stale_key,
                        "name": stale_name,
                        "error": delete_response.text,
                    }
                )

        return deleted_tools, failed_deletes

    def _refresh_tool_cache(self, external_app_id: str, partial: bool) -> None:
        """Refresh the in-memory tool cache after batch mutations.

        Args:
            external_app_id: App identifier (used only for log context).
            partial: True when called after a failed upsert (rollback path).
        """
        try:
            self.handler.tool_manager.refresh_custom_tools(self.session_key)
        except Exception as exc:  # pragma: no cover - defensive
            if partial:
                logger.warning(
                    f"Failed to refresh tool cache after partial batch replace for app '{external_app_id}': {exc}"
                )
            else:
                logger.warning(
                    f"Failed to refresh tool cache after batch replace for app '{external_app_id}': {exc}"
                )


class MCPToolsRestHandler(PersistentServerConnectionApplication):
    """
    Persistent REST handler that will manage MCP tool definitions.

    Only the POST method is implemented for now; requests for other HTTP
    verbs will receive a 501 Not Implemented response.
    """

    def __init__(self, command_line: str, command_arg: str) -> None:
        super().__init__()
        self.settings = MCPSettings.get()
        self.tool_manager = get_default_manager(reload=False)
        logger.info("Initializing MCP Tools REST handler")

    def handle(self, in_string: str) -> Dict[str, Any]:
        update_log_context_req_id()

        try:
            request = self._parse_request(in_string)
        except ValueError as exc:
            logger.warning("Failed to parse MCP tools request: %s", exc)
            return self._build_response(
                400,
                {
                    "error": True,
                    "code": "invalid_request",
                    "message": str(exc),
                },
            )

        caller = (request.get("session") or {}).get("user")
        if caller:
            update_log_context(username=caller)

        MCPSettings.set_splunkd_url_from_request(request)

        logger.info(
            "MCP tools request: method=%s", request.get("method", "GET").upper()
        )

        method = request.get("method", "GET").upper()
        handler = {
            "GET": self._handle_get,
            "POST": self._handle_post,
            "PUT": self._handle_put,
            "DELETE": self._handle_delete,
        }.get(method)

        if handler is None:
            logger.warning("Unsupported method %s for /mcp_tools", method)
            return self._build_response(
                405,
                {
                    "error": True,
                    "code": "method_not_allowed",
                    "message": f"Method {method} is not allowed for /mcp_tools",
                    "allowed_methods": sorted(_ALLOWED_HTTP_METHODS),
                },
            )

        try:
            status, payload = handler(request)
            return self._build_response(status, payload)
        except NotImplementedError as exc:
            logger.info("MCP tools endpoint invoked before implementation: %s", method)
            return self._build_response(
                501,
                {
                    "error": True,
                    "code": "not_implemented",
                    "message": str(exc),
                },
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            logger.exception("Unexpected error handling %s request", method)
            return self._build_response(
                500,
                {
                    "error": True,
                    "code": "internal_error",
                    "message": f"Failed to process {method} request: {exc}",
                },
            )
        finally:
            clear_log_context()

    def _parse_request(self, in_string: str) -> Dict[str, Any]:
        if not in_string:
            raise ValueError("Request body is required")

        try:
            request = json.loads(in_string)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid request format: {exc}") from exc

        payload = request.get("payload")
        request["parsed_payload"] = self._parse_payload(payload)
        request["query"] = self._normalize_query_params(request.get("query"))
        return request

    def _normalize_query_params(self, query: Any) -> Dict[str, Any]:
        if not query:
            return {}

        if isinstance(query, dict):
            return query

        normalized: Dict[str, Any] = {}
        if isinstance(query, list):
            for item in query:
                if (
                    isinstance(item, (list, tuple))
                    and len(item) == 2
                    and isinstance(item[0], str)
                ):
                    normalized[item[0]] = item[1]
        return normalized

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
                return payload

        return payload

    def _handle_get(self, request: Dict[str, Any]) -> Response:
        session_key = self._extract_session_key(request)
        if not session_key:
            return (
                401,
                {
                    "error": True,
                    "code": "missing_auth",
                    "message": "A valid session or system auth token is required.",
                },
            )

        query_params = request.get("query") or {}
        if "enabled_tools" in query_params:
            return self._handle_enabled_tools_get(session_key)

        self.tool_manager.refresh_custom_tools(session_key)
        tool_id = query_params.get("tool_id")
        tool_name_param = query_params.get("name")
        app_id_param = query_params.get("external_app_id")

        if (
            isinstance(tool_name_param, str)
            and tool_name_param.strip()
            and isinstance(app_id_param, str)
            and app_id_param.strip()
        ):
            tool_id = f"{app_id_param.strip()}:{tool_name_param.strip()}"

        if isinstance(tool_id, str) and tool_id.strip():
            tool = self.tool_manager.tools.get(tool_id.strip())
            if not tool:
                return (
                    404,
                    {
                        "error": True,
                        "code": "tool_not_found",
                        "message": f"Tool '{tool_id}' does not exist.",
                    },
                )
            return 200, {"tool": tool.to_external_dict()}

        logger.info("Processing internal list_tools request")
        tools = list(self.tool_manager.tools.values())
        external_app_filter = query_params.get("external_app_id")
        if isinstance(external_app_filter, str) and external_app_filter.strip():
            app_id = external_app_filter.strip()
            tools = [
                tool for tool in tools if getattr(tool, "external_app", None) == app_id
            ]
        tool_name_filter = query_params.get("name")
        if isinstance(tool_name_filter, str) and tool_name_filter.strip():
            target_name = tool_name_filter.strip()
            tools = [tool for tool in tools if tool.name == target_name]

        tags_filter = query_params.get("tags")
        if tags_filter:
            if isinstance(tags_filter, str):
                tag_values = [
                    tag.strip() for tag in tags_filter.split(",") if tag.strip()
                ]
            elif isinstance(tags_filter, list):
                tag_values = [
                    str(tag).strip() for tag in tags_filter if str(tag).strip()
                ]
            else:
                tag_values = []

            if tag_values:
                tag_set = set(tag_values)
                tools = [
                    tool
                    for tool in tools
                    if tag_set.intersection(set(getattr(tool, "tags", []) or []))
                ]

        serialized = [tool.to_external_dict() for tool in tools]
        return (
            200,
            {
                "tools": serialized,
                "total": len(serialized),
            },
        )

    def _handle_enabled_tools_get(self, session_key: str) -> Response:
        try:
            enabled_tools = self.tool_manager.list_enabled_tools(session_key)
        except ToolCollectionError as e:
            logger.error("Failed to retrieve enabled tools: %s", e)
            return (
                500,
                {
                    "error": True,
                    "code": "enabled_tool_failed",
                    "message": "Failed to retrieve enabled tools.",
                    "details": str(e),
                },
            )
        enabled_tools_api_model = [
            enabled_tool.to_api_model() for enabled_tool in enabled_tools
        ]
        return 200, {"enabled_tools": enabled_tools_api_model}

    def _handle_put(self, request: Dict[str, Any]) -> Response:
        payload = request.get("parsed_payload")
        if not isinstance(payload, dict):
            return (
                400,
                {
                    "error": True,
                    "code": "invalid_payload",
                    "message": "PUT body must be a JSON object.",
                },
            )

        tool_id_raw = payload.get("tool_id")
        tool_id = tool_id_raw.strip() if isinstance(tool_id_raw, str) else None
        if not tool_id:
            return (
                400,
                {
                    "error": True,
                    "code": "missing_tool_id",
                    "message": "'tool_id' is required to update a tool.",
                },
            )

        session_key = self._extract_session_key(request)
        if not session_key:
            return (
                401,
                {
                    "error": True,
                    "code": "missing_auth",
                    "message": "A valid session or system auth token is required.",
                },
            )

        kv_manager = self._create_kv_manager(session_key)
        response = kv_manager.get(tool_id)
        if response.status_code == 404:
            return (
                404,
                {
                    "error": True,
                    "code": "tool_not_found",
                    "message": f"Tool '{tool_id}' does not exist.",
                },
            )

        if response.status_code != 200:
            logger.error(
                "KV Store get failed for '%s' (%s): %s",
                tool_id,
                response.status_code,
                response.text,
            )
            failure_detail = self._safe_json(response)
            return (
                response.status_code,
                {
                    "error": True,
                    "code": "kvstore_error",
                    "message": "Failed to retrieve tool for update.",
                    "details": failure_detail,
                },
            )

        tool_doc = self._safe_json(response)
        if not isinstance(tool_doc, dict):
            logger.error(
                "KV Store returned unexpected data for tool '%s': %s",
                tool_id,
                tool_doc,
            )
            return (
                502,
                {
                    "error": True,
                    "code": "kvstore_response_error",
                    "message": "KV Store returned malformed tool data.",
                },
            )

        _, is_built_in = self._extract_tool_meta_flags(tool_doc)
        if is_built_in:
            return (
                409,
                {
                    "error": True,
                    "code": "built_in_tool",
                    "message": "Built-in tools cannot be updated.",
                },
            )

        updates = {
            key: value
            for key, value in payload.items()
            if key not in {"tool_id", "_key"}
        }

        if not updates:
            return (
                400,
                {
                    "error": True,
                    "code": "no_updates",
                    "message": "No fields provided to update.",
                },
            )

        if "name" in updates and updates["name"] != tool_doc.get("name"):
            return (
                409,
                {
                    "error": True,
                    "code": "immutable_field",
                    "message": "Tool name cannot be modified.",
                },
            )

        meta_updates = updates.get("_meta")
        if meta_updates is not None:
            if not isinstance(meta_updates, dict):
                return (
                    400,
                    {
                        "error": True,
                        "code": "invalid_meta",
                        "message": "'_meta' must be an object.",
                    },
                )
            existing_meta = tool_doc.get("_meta") or {}
            existing_app_id = existing_meta.get("external_app_id")
            incoming_app_id = meta_updates.get("external_app_id")
            if (
                incoming_app_id is not None
                and existing_app_id is not None
                and incoming_app_id != existing_app_id
            ):
                return (
                    409,
                    {
                        "error": True,
                        "code": "immutable_field",
                        "message": "external_app_id cannot be modified.",
                    },
                )

        updated_doc = deepcopy(tool_doc)
        self._merge_dicts(updated_doc, updates)

        replace_response = kv_manager.replace(tool_id, updated_doc)
        if replace_response.status_code not in (200, 201):
            logger.error(
                "KV Store replace failed for '%s' (%s): %s",
                tool_id,
                replace_response.status_code,
                replace_response.text,
            )
            failure_detail = self._safe_json(replace_response)
            return (
                replace_response.status_code,
                {
                    "error": True,
                    "code": "kvstore_error",
                    "message": "Failed to update tool.",
                    "details": failure_detail,
                },
            )

        try:
            self.tool_manager.refresh_custom_tools(session_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to refresh tool cache after update: %s", exc)

        return (
            200,
            {
                "tool_id": tool_id,
                "tool": updated_doc,
            },
        )

    def _handle_delete(self, request: Dict[str, Any]) -> Response:
        payload = request.get("parsed_payload")
        if not isinstance(payload, dict):
            return (
                400,
                {
                    "error": True,
                    "code": "invalid_payload",
                    "message": "DELETE body must be a JSON object with 'tool_id' or 'external_app_id'.",
                },
            )

        tool_id_raw = payload.get("tool_id")
        tool_id = tool_id_raw.strip() if isinstance(tool_id_raw, str) else None
        external_app_id_raw = payload.get("external_app_id")
        external_app_id = (
            external_app_id_raw.strip()
            if isinstance(external_app_id_raw, str)
            else None
        )

        if not tool_id and not external_app_id:
            return (
                400,
                {
                    "error": True,
                    "code": "missing_identifier",
                    "message": "Either 'tool_id' or 'external_app_id' is required to delete tools.",
                },
            )

        session_key = self._extract_session_key(request)
        if not session_key:
            return (
                401,
                {
                    "error": True,
                    "code": "missing_auth",
                    "message": "A valid session or system auth token is required.",
                },
            )

        # If tool_id is provided, delete single tool
        if tool_id:
            return self._delete_single_tool(tool_id, session_key)

        # Otherwise, delete all tools by external_app_id
        return self._delete_tools_by_app(external_app_id, session_key)

    def _delete_single_tool(self, tool_id: str, session_key: str) -> Response:
        """Delete a single tool by its tool_id."""
        manager_tool = self._find_tool_by_key(tool_id)
        if manager_tool and manager_tool.built_in:
            return (
                409,
                {
                    "error": True,
                    "code": "built_in_tool",
                    "message": f"Tool '{manager_tool.name}' is built-in and cannot be deleted.",
                },
            )

        kv_manager = self._create_kv_manager(session_key)

        response = kv_manager.get(tool_id)
        if response.status_code == 404:
            return (
                404,
                {
                    "error": True,
                    "code": "tool_not_found",
                    "message": f"Tool '{tool_id}' does not exist.",
                },
            )

        if response.status_code != 200:
            logger.error(
                "KV Store get failed for '%s' (%s): %s",
                tool_id,
                response.status_code,
                response.text,
            )
            failure_detail = self._safe_json(response)
            return (
                response.status_code,
                {
                    "error": True,
                    "code": "kvstore_error",
                    "message": "Failed to retrieve tool for deletion.",
                    "details": failure_detail,
                },
            )

        tool_doc = self._safe_json(response)
        if not isinstance(tool_doc, dict):
            logger.error(
                "KV Store returned unexpected data for tool '%s': %s",
                tool_id,
                tool_doc,
            )
            return (
                502,
                {
                    "error": True,
                    "code": "kvstore_response_error",
                    "message": "KV Store returned malformed tool data.",
                },
            )

        _, is_built_in = self._extract_tool_meta_flags(tool_doc)
        if is_built_in:
            tool_name = tool_doc.get("name", tool_id)
            logger.info("Attempt to delete built-in tool '%s' (%s)", tool_name, tool_id)
            return (
                409,
                {
                    "error": True,
                    "code": "built_in_tool",
                    "message": f"Tool '{tool_name}' is built-in and cannot be deleted.",
                },
            )

        delete_response = kv_manager.delete(tool_id)
        if not self._is_kv_status(delete_response, (200, 204)):
            logger.error(
                "KV Store delete failed for '%s' (%s): %s",
                tool_id,
                delete_response.status_code,
                delete_response.text,
            )
            failure_detail = self._safe_json(delete_response)
            return (
                delete_response.status_code,
                {
                    "error": True,
                    "code": "kvstore_error",
                    "message": "Failed to delete tool.",
                    "details": failure_detail,
                },
            )

        logger.info(
            "Deleted tool '%s' (%s)",
            tool_doc.get("name", tool_id),
            tool_id,
        )

        # Clean up the enabled entry for the deleted tool.
        deleted_tool_name = tool_doc.get("name")
        if deleted_tool_name:
            self._cleanup_enabled_entries([deleted_tool_name], session_key)

        self.tool_manager.invalidate_enabled_tool_cache()
        try:
            self.tool_manager.refresh_custom_tools(session_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to refresh tool cache after delete: %s", exc)

        return (
            200,
            {
                "deleted": True,
                "tool_id": tool_id,
                "message": "Tool deleted successfully.",
            },
        )

    def _delete_tools_by_app(self, external_app_id: str, session_key: str) -> Response:
        """Delete all tools belonging to an external app."""
        kv_manager = self._create_kv_manager(session_key)

        # Query all tools from KV Store
        query_response = kv_manager.query(output_mode="json", count="0")
        if query_response.status_code != 200:
            logger.error(
                "KV Store query failed for bulk delete (%s): %s",
                query_response.status_code,
                query_response.text,
            )
            failure_detail = self._safe_json(query_response)
            return (
                query_response.status_code,
                {
                    "error": True,
                    "code": "kvstore_error",
                    "message": "Failed to query tools for deletion.",
                    "details": failure_detail,
                },
            )

        try:
            all_tools = query_response.json()
        except ValueError:
            logger.error("Failed to decode KV Store response: %s", query_response.text)
            return (
                502,
                {
                    "error": True,
                    "code": "kvstore_response_error",
                    "message": "KV Store returned malformed data.",
                },
            )

        if not isinstance(all_tools, list):
            return (
                502,
                {
                    "error": True,
                    "code": "kvstore_response_error",
                    "message": "KV Store returned unexpected data format.",
                },
            )

        # Filter tools by external_app_id
        tools_to_delete = []
        for tool_doc in all_tools:
            if not isinstance(tool_doc, dict):
                continue
            meta = tool_doc.get("_meta", {})
            if not isinstance(meta, dict):
                continue
            tool_app_id = meta.get("external_app_id")
            if tool_app_id == external_app_id:
                tools_to_delete.append(tool_doc)

        if not tools_to_delete:
            return (
                404,
                {
                    "error": True,
                    "code": "no_tools_found",
                    "message": f"No tools found for external_app_id '{external_app_id}'.",
                },
            )

        # Delete each tool, tracking results
        deleted_tools = []
        skipped_built_in = []
        failed_deletes = []

        for tool_doc in tools_to_delete:
            tool_id = tool_doc.get("_key")
            tool_name = tool_doc.get("name", tool_id)

            if not tool_id:
                continue

            # Check if built-in
            _, is_built_in = self._extract_tool_meta_flags(tool_doc)
            if is_built_in:
                skipped_built_in.append({"tool_id": tool_id, "name": tool_name})
                logger.info(
                    "Skipping built-in tool '%s' (%s) during bulk delete",
                    tool_name,
                    tool_id,
                )
                continue

            # Delete the tool
            delete_response = kv_manager.delete(tool_id)
            if self._is_kv_status(delete_response, (200, 204)):
                deleted_tools.append({"tool_id": tool_id, "name": tool_name})
                logger.info("Bulk deleted tool '%s' (%s)", tool_name, tool_id)
            else:
                failed_deletes.append(
                    {
                        "tool_id": tool_id,
                        "name": tool_name,
                        "error": delete_response.text,
                    }
                )
                logger.error(
                    "Failed to delete tool '%s' (%s): %s",
                    tool_name,
                    tool_id,
                    delete_response.text,
                )

        # Clean up enabled entries for successfully deleted tools.
        self._cleanup_enabled_entries(
            self._extract_tool_names(deleted_tools),
            session_key,
        )

        # Refresh tool cache
        self.tool_manager.invalidate_enabled_tool_cache()
        try:
            self.tool_manager.refresh_custom_tools(session_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to refresh tool cache after bulk delete: %s", exc)

        # Build response
        response_data: Dict[str, Any] = {
            "external_app_id": external_app_id,
            "message": "All tools from this app are deleted.",
            "deleted_count": len(deleted_tools),
        }

        if deleted_tools:
            response_data["deleted_tools"] = deleted_tools

        if skipped_built_in:
            response_data["skipped_built_in"] = skipped_built_in
            response_data["message"] = (
                "Tools deleted successfully. Some built-in tools were skipped."
            )

        if failed_deletes:
            response_data["failed_deletes"] = failed_deletes
            response_data["message"] = (
                "Some tools could not be deleted. See 'failed_deletes' for details."
            )

        return (200, response_data)

    def _handle_enable_toggle(
        self, payload: Dict[str, Any], session_key: str
    ) -> Response:
        tool_id_raw = payload.get("tool_id")
        enabled_flag = payload.get("enabled")
        override_flag = bool(payload.get("override"))
        tool_name_raw = payload.get("tool_name")

        if not isinstance(tool_id_raw, str) or not tool_id_raw.strip():
            return (
                400,
                {
                    "error": True,
                    "code": "missing_tool_id",
                    "message": "'tool_id' is required and must be a string.",
                },
            )

        tool_id = tool_id_raw.strip()
        tool_name = tool_name_raw.strip() if isinstance(tool_name_raw, str) else ""

        def _infer_tool_name() -> Optional[str]:
            try:
                self.tool_manager.refresh_custom_tools(session_key)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to refresh tools while inferring name: %s", exc)

            # Only infer when the exact tool_id is present to avoid cross-app collisions.
            tool_obj = self.tool_manager.tools.get(tool_id)
            if tool_obj:
                return tool_obj.name
            return None

        # When enabling, allow tool_name to be omitted if we can infer it from tool_id
        if enabled_flag and not tool_name:
            inferred = _infer_tool_name()
            if not inferred:
                return (
                    400,
                    {
                        "error": True,
                        "code": "missing_tool_name",
                        "message": (
                            "Cannot delete tool with provided tool_id alone. "
                            "Please include both tool_id and tool_name."
                        ),
                    },
                )
            tool_name = inferred

        if not enabled_flag and not tool_name:
            # Infer tool name for disable using tool_id
            inferred = _infer_tool_name()
            if not inferred:
                return (
                    400,
                    {
                        "error": True,
                        "code": "missing_tool_name",
                        "message": (
                            "'tool_name' is required unless it can be inferred from "
                            "'tool_id'. Multiple tools may share the same suffix across "
                            "apps, so provide both tool_name and tool_id to delete the "
                            "intended tool."
                        ),
                    },
                )
            tool_name = inferred

        if not isinstance(enabled_flag, bool):
            return (
                400,
                {
                    "error": True,
                    "code": "missing_enabled_flag",
                    "message": "'enabled' is required and must be a boolean.",
                },
            )

        if enabled_flag:
            try:
                self.tool_manager.refresh_custom_tools(session_key)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Failed to refresh tools before enable: %s", exc)

            tool_obj = self.tool_manager.tools.get(tool_id)
            if not tool_obj:
                return (
                    404,
                    {
                        "error": True,
                        "code": "tool_not_found",
                        "message": f"Tool '{tool_id}' does not exist.",
                    },
                )

            required_app = getattr(tool_obj, "required_app", None)
            if required_app:
                apps_result = get_installed_apps(session_key)
                installed_apps = apps_result.get("apps")
                if installed_apps is None:
                    return (
                        502,
                        {
                            "error": True,
                            "code": "apps_lookup_failed",
                            "message": "Failed to verify required app installation.",
                            "details": apps_result.get("error"),
                        },
                    )
                if required_app not in installed_apps:
                    return (
                        409,
                        {
                            "error": True,
                            "code": "required_app_missing",
                            "message": (
                                f"Cannot enable tool '{tool_name}': "
                                f"required app '{required_app}' is not installed."
                            ),
                            "required_app": required_app,
                            "tool_id": tool_id,
                        },
                    )

            try:
                status_code, error_payload = self.tool_manager.enable_tool(
                    tool_name, tool_id, session_key, override=override_flag
                )
            except ToolCollectionError as e:
                logger.exception(
                    "Error enabling tool '%s' (%s): %s", tool_name, tool_id, str(e)
                )
                return (
                    500,
                    {
                        "error": True,
                        "code": "tool_enable_failed",
                        "message": f"Failed to enable tool: {str(e)}",
                    },
                )
            if status_code not in (200, 201):
                return (
                    status_code,
                    error_payload
                    or {
                        "error": True,
                        "code": "tool_enabled_failed",
                        "message": "Failed to enable tool.",
                    },
                )
            logger.info("Enabled tool '%s' with id '%s'", tool_name, tool_id)
            log_telemetry(
                EVENT_TOOL_ENABLED,
                http.HTTPStatus.OK,
                tool_name=tool_name,
                override=bool(override_flag),
            )
            return (
                200,
                {
                    "tool_id": tool_id,
                    "enabled": True,
                    "message": "Tool enabled successfully.",
                },
            )

        try:
            status_code, error_detail = self.tool_manager.disable_tool(
                tool_name, tool_id, session_key
            )
        except ToolCollectionError as e:
            logger.exception(
                "Error disabling tool '%s' (%s): %s", tool_name, tool_id, str(e)
            )
            return (
                500,
                {
                    "error": True,
                    "code": "tool_disabled_failed",
                    "message": f"Failed to disable tool: {str(e)}",
                },
            )
        if status_code not in (200, 204):
            return (
                status_code,
                error_detail
                or {
                    "error": True,
                    "code": "tool_disabled_failed",
                    "message": "Failed to disable tool.",
                    "details": error_detail,
                },
            )

        log_telemetry(
            EVENT_TOOL_DISABLED,
            http.HTTPStatus.OK,
            tool_name=tool_name,
        )
        return (
            200,
            {
                "tool_id": tool_id,
                "enabled": False,
                "message": "Tool disabled successfully.",
            },
        )

    def _handle_post(self, request: Dict[str, Any]) -> Response:
        payload = request.get("parsed_payload")
        if not isinstance(payload, dict):
            return (
                400,
                {
                    "error": True,
                    "code": "invalid_payload",
                    "message": "POST body must be a JSON object.",
                },
            )

        session_key = self._extract_session_key(request)
        if not session_key:
            return (
                401,
                {
                    "error": True,
                    "code": "missing_auth",
                    "message": "A valid session or system auth token is required.",
                },
            )

        enable_fields = {"tool_name", "tool_id", "enabled", "override"}
        payload_keys = set(payload.keys()) if payload else set()
        if payload_keys and payload_keys.issubset(enable_fields):
            return self._handle_enable_toggle(payload, session_key)

        if "external_app_id" in payload and "tools" in payload:
            return self._handle_batch_replace(payload, session_key, request)

        try:
            tool_doc = self._normalize_tool_definition(payload, request)
        except ToolValidationError as exc:
            return (
                400,
                {
                    "error": True,
                    "code": "validation_error",
                    "message": "Tool definition failed validation.",
                    "details": exc.errors,
                },
            )

        kv_manager = self._create_kv_manager(session_key)

        conflict_msg, conflict_status = self._check_tool_name_conflict(
            kv_manager, tool_doc
        )
        if conflict_msg:
            return (
                conflict_status,
                {
                    "error": True,
                    "code": "name_conflict",
                    "message": conflict_msg,
                },
            )

        response = kv_manager.insert(tool_doc)

        if response.status_code not in (200, 201):
            logger.error(
                "KV Store insert failed (%s): %s",
                response.status_code,
                response.text,
            )
            failure_detail = self._safe_json(response)
            return (
                response.status_code,
                {
                    "error": True,
                    "code": "kvstore_error",
                    "message": "Failed to store tool definition.",
                    "details": failure_detail,
                },
            )

        kv_result = self._safe_json(response)
        tool_id = tool_doc.get("_key")
        if not tool_id and isinstance(kv_result, dict):
            tool_id = kv_result.get("_key")

        if not tool_id:
            logger.error("KV Store response missing _key: %s", kv_result)
            return (
                502,
                {
                    "error": True,
                    "code": "kvstore_response_error",
                    "message": "Tool stored but KV Store did not return an ID.",
                },
            )

        logger.info("Created custom tool '%s' with id '%s'", tool_doc["name"], tool_id)

        try:
            self.tool_manager.refresh_custom_tools(session_key)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to refresh tool cache after create: %s", exc)

        creation_response = (
            201,
            {
                "tool_id": tool_id,
            },
        )

        if "enabled" not in payload:
            return creation_response

        toggle_payload = {
            "tool_name": tool_doc["name"],
            "tool_id": tool_id,
            "enabled": payload.get("enabled"),
            "override": payload.get("override"),
        }
        toggle_status, toggle_body = self._handle_enable_toggle(
            toggle_payload, session_key
        )
        if toggle_status != 200:
            return (toggle_status, toggle_body)

        return creation_response

    def _handle_batch_replace(
        self, payload: Dict[str, Any], session_key: str, request: Dict[str, Any]
    ) -> Response:
        """Delegate to BatchReplaceToolsService for app-scoped tool replacement."""
        return BatchReplaceToolsService(self, session_key, request).execute(payload)

    def _normalize_tool_definition(
        self, payload: Dict[str, Any], request: Dict[str, Any]
    ) -> Dict[str, Any]:
        errors: List[str] = []

        allowed_fields = {"name", _FIELD_TITLE, "description", "inputSchema", "_meta"}
        unknown_fields = set(payload.keys()) - allowed_fields
        if unknown_fields:
            errors.append(
                f"Unexpected fields in tool definition: {', '.join(sorted(unknown_fields))}"
            )

        name = self._require_name(payload, errors)
        title = self._require_string(payload, _FIELD_TITLE, errors)
        description = self._require_string(payload, "description", errors)

        input_schema = self._sanitize_input_schema(payload.get("inputSchema"), errors)
        meta_block = self._sanitize_meta_block(payload.get("_meta"), errors)
        external_app_id = meta_block.get("external_app_id")

        if errors:
            raise ToolValidationError(errors)

        # Prefix tool name with external_app_id and underscore, only if not already present
        if external_app_id and not name.startswith(f"{external_app_id}_"):
            name = f"{external_app_id}_{name}"

        sanitized = {
            "name": name,
            _FIELD_TITLE: title,
            "description": description,
            "inputSchema": input_schema,
            "_meta": meta_block,
        }
        if external_app_id:
            sanitized["_key"] = f"{external_app_id}:{name}"
        return sanitized

    def _sanitize_input_schema(
        self, raw_schema: Any, errors: List[str]
    ) -> Dict[str, Any]:
        if not isinstance(raw_schema, dict):
            errors.append("'inputSchema' must be an object.")
            return {}

        allowed_schema_fields = {"type", "properties", "required", _FIELD_TITLE}
        unknown_schema_fields = set(raw_schema.keys()) - allowed_schema_fields
        if unknown_schema_fields:
            errors.append(
                f"Unexpected fields in 'inputSchema': {', '.join(sorted(unknown_schema_fields))}"
            )

        schema_type = raw_schema.get("type", "object")
        if schema_type != "object":
            errors.append("'inputSchema.type' must be 'object'.")

        properties = raw_schema.get("properties")
        if not isinstance(properties, dict):
            errors.append("'inputSchema.properties' must be an object.")
            properties = {}

        sanitized_props: Dict[str, Any] = {}
        allowed_prop_fields = {
            "type",
            "description",
            "default",
            "enum",
            "minimum",
            "maximum",
            "pattern",
            "validation_message",
            _FIELD_TITLE,
            "examples",
            "meta",
        }

        for key, value in properties.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                errors.append(
                    "Each property in 'inputSchema.properties' must be an object."
                )
                continue

            unknown_prop_fields = set(value.keys()) - allowed_prop_fields
            if unknown_prop_fields:
                errors.append(
                    f"Unexpected fields in inputSchema.properties['{key}']: "
                    f"{', '.join(sorted(unknown_prop_fields))}"
                )

            sanitized_props[key] = value

        sanitized_schema: Dict[str, Any] = {
            "type": "object",
            "properties": sanitized_props,
        }
        title = raw_schema.get(_FIELD_TITLE)
        if title:
            sanitized_schema[_FIELD_TITLE] = title
        required = raw_schema.get("required")
        if isinstance(required, list):
            sanitized_required = [
                str(item) for item in required if isinstance(item, str)
            ]
            if sanitized_required:
                sanitized_schema["required"] = sanitized_required

        return sanitized_schema

    def _sanitize_meta_block(self, meta: Any, errors: List[str]) -> Dict[str, Any]:
        if not isinstance(meta, dict):
            errors.append("'_meta' must be an object.")
            return {}

        allowed_meta_fields = {
            "external_app_id",
            "tags",
            "examples",
            "required_app",
            "execution",
            _FIELD_SAVED_SEARCH,
            "name_prefix",
        }
        unknown_meta_fields = set(meta.keys()) - allowed_meta_fields
        if unknown_meta_fields:
            errors.append(
                f"Unexpected fields in '_meta': {', '.join(sorted(unknown_meta_fields))}"
            )

        sanitized: Dict[str, Any] = {}
        tags = self._sanitize_tags(meta.get("tags"), errors)
        sanitized["tags"] = tags

        examples = self._sanitize_examples(meta.get("examples"), errors)
        sanitized["examples"] = examples

        required_app = self._optional_string(
            meta.get("required_app"), "required_app", errors
        )
        if required_app:
            sanitized["required_app"] = required_app

        external_app_id = self._optional_string(
            meta.get("external_app_id"), "external_app_id", errors, required=True
        )
        if external_app_id:
            sanitized["external_app_id"] = external_app_id

        execution = self._sanitize_execution(meta.get("execution"), errors)
        sanitized["execution"] = execution

        saved_search = meta.get(_FIELD_SAVED_SEARCH)
        if isinstance(saved_search, dict):
            sanitized[_FIELD_SAVED_SEARCH] = saved_search

        return sanitized

    def _sanitize_execution(self, execution: Any, errors: List[str]) -> Dict[str, Any]:
        if not isinstance(execution, dict):
            errors.append("'_meta.execution' must be an object.")
            return {}

        exec_type = str(execution.get("type", "spl")).lower()
        sanitized: Dict[str, Any] = {"type": exec_type}

        if exec_type == "spl":
            allowed_fields = {
                "type",
                "template",
                "row_limiter",
                "time_range",
                "guardrails",
            }
        elif exec_type == "api":
            allowed_fields = {"type", "method", "endpoint", "headers", "params", "body"}
        else:
            errors.append("execution.type must be either 'spl' or 'api'.")
            allowed_fields = set()

        unknown_exec_fields = set(execution.keys()) - allowed_fields
        if unknown_exec_fields:
            errors.append(
                f"Unexpected fields in '_meta.execution': {', '.join(sorted(unknown_exec_fields))}"
            )

        if exec_type == "spl":
            template = execution.get("template")
            if not isinstance(template, str) or not template.strip():
                errors.append("'_meta.execution.template' must be a non-empty string.")
            else:
                sanitized["template"] = template.strip()

            if any(
                field in execution
                for field in ("method", "endpoint", "headers", "params", "body")
            ):
                errors.append("SPL execution cannot include API-specific fields.")

            sanitized["row_limiter"] = bool(execution.get("row_limiter", True))
            sanitized["time_range"] = bool(execution.get("time_range", True))
            if "guardrails" in execution:
                sanitized["guardrails"] = bool(execution.get("guardrails"))

        elif exec_type == "api":
            method = execution.get("method")
            endpoint = execution.get("endpoint")
            if not isinstance(method, str) or not method.strip():
                errors.append("API tools require a HTTP 'method'.")
            else:
                sanitized["method"] = method.strip().upper()

            if not isinstance(endpoint, str) or not endpoint.strip():
                errors.append("API tools require a non-empty 'endpoint'.")
            else:
                sanitized["endpoint"] = endpoint.strip()

            if execution.get("template"):
                errors.append("API execution cannot include SPL templates.")

            headers = execution.get("headers")
            if headers is not None:
                if isinstance(headers, dict):
                    sanitized["headers"] = deepcopy(headers)
                else:
                    errors.append("API 'headers' must be an object if provided.")

            params = execution.get("params")
            if params is not None:
                if isinstance(params, dict):
                    sanitized["params"] = deepcopy(params)
                else:
                    errors.append("API 'params' must be an object if provided.")

            if "body" in execution:
                sanitized["body"] = deepcopy(execution.get("body"))

        else:
            errors.append("execution.type must be either 'spl' or 'api'.")

        return sanitized

    def _sanitize_examples(
        self, raw_examples: Any, errors: List[str]
    ) -> List[Dict[str, Any]]:
        if raw_examples is None:
            return []
        if not isinstance(raw_examples, list):
            errors.append("'examples' must be an array when provided.")
            return []

        sanitized: List[Dict[str, Any]] = []
        for idx, example in enumerate(raw_examples):
            if not isinstance(example, dict):
                errors.append(f"Example at index {idx} must be an object.")
                continue

            allowed_fields = {"name", "description", "expected_use", "arguments"}
            unknown_fields = set(example.keys()) - allowed_fields
            if unknown_fields:
                errors.append(
                    f"Unexpected fields in example at index {idx}: "
                    f"{', '.join(sorted(unknown_fields))}"
                )

            example_def: Dict[str, Any] = {}
            for field in ("name", "description", "expected_use"):
                if field in example:
                    value = example.get(field)
                    if isinstance(value, str):
                        example_def[field] = value
                    else:
                        errors.append(
                            f"Example at index {idx} '{field}' must be a string."
                        )

            if "arguments" in example:
                args = example.get("arguments")
                if isinstance(args, dict):
                    example_def["arguments"] = args
                else:
                    errors.append(
                        f"Example at index {idx} arguments must be an object."
                    )

            sanitized.append(example_def)

        return sanitized

    def _sanitize_tags(self, raw_tags: Any, errors: List[str]) -> List[str]:
        if raw_tags is None:
            return []
        if not isinstance(raw_tags, list):
            errors.append("'tags' must be an array when provided.")
            return []

        sanitized: List[str] = []
        for tag in raw_tags:
            if isinstance(tag, str):
                trimmed = tag.strip()
                if trimmed:
                    sanitized.append(trimmed)
        # Deduplicate while preserving order
        seen = set()
        ordered: List[str] = []
        for tag in sanitized:
            if tag not in seen:
                seen.add(tag)
                ordered.append(tag)
        return ordered

    def _require_name(
        self, payload: Dict[str, Any], errors: List[str]
    ) -> Optional[str]:
        name = self._require_string(payload, "name", errors)
        if name and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            errors.append(
                "Tool 'name' must start with a letter and contain only "
                "letters, digits, or underscores."
            )
        return name

    def _require_string(
        self, payload: Dict[str, Any], field: str, errors: List[str]
    ) -> Optional[str]:
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"Field '{field}' is required and must be a string.")
            return None
        return value.strip()

    def _optional_string(
        self,
        value: Any,
        field: str,
        errors: List[str],
        required: bool = False,
    ) -> Optional[str]:
        if value is None:
            if required:
                errors.append(f"Field '{field}' is required.")
            return None
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed:
                return trimmed
            return None
        errors.append(f"Field '{field}' must be a string when provided.")
        return None

    def _require_bool(
        self, payload: Dict[str, Any], field: str, errors: List[str]
    ) -> bool:
        value = payload.get(field)
        if isinstance(value, bool):
            return value
        errors.append(f"Field '{field}' must be a boolean.")
        return False

    def _extract_session_key(self, request: Dict[str, Any]) -> Optional[str]:
        # Prefer caller auth so KV operations honor the user's app permissions.
        # Some deployments return a system token that cannot access app KV data.
        return (
            ((request.get("session") or {}).get("authtoken"))
            or request.get("system_authtoken")
            or request.get("systemAuthtoken")
        )

    def _check_tool_name_conflict(
        self, kv_manager: KVStoreManager, tool_doc: Dict[str, Any]
    ) -> Tuple[Optional[str], int]:
        tool_name = tool_doc["name"]
        tool_external_app, tool_built_in = self._extract_tool_meta_flags(tool_doc)

        # Built-in tools only conflict if both external_app_id and built_in match.
        if self.tool_manager:
            for existing_tool in self.tool_manager.tools.values():
                if (
                    existing_tool.name == tool_name
                    and (existing_tool.external_app) == tool_external_app
                    and existing_tool.built_in == tool_built_in
                ):
                    if existing_tool.external_app == "splunk_mcp_app":
                        return (
                            "A custom tool with the same name already exists.",
                            409,
                        )
                    else:
                        return (
                            "Tool with the same name and external_app_id already exists.",
                            409,
                        )

        response = kv_manager.query({"name": tool_name}, output_mode="json", count="0")

        if response.status_code == 200:
            existing = self._safe_json(response)
            if isinstance(existing, list) and existing:
                for record in existing:
                    record_app, record_built_in = self._extract_tool_meta_flags(record)
                    if (
                        record_app == tool_external_app
                        and record_built_in == tool_built_in
                    ):
                        return (
                            f"Tool '{tool_name}' already exists in KV Store.",
                            409,
                        )
            return (None, 0)

        if response.status_code == 404:
            return (None, 0)

        logger.error(
            "Unable to verify uniqueness for '%s': %s",
            tool_name,
            response.text,
        )
        return ("Unable to verify tool uniqueness at this time.", 502)

    def _extract_tool_meta_flags(
        self, tool_doc: Dict[str, Any]
    ) -> Tuple[Optional[str], bool]:
        meta = tool_doc.get("_meta")
        external_app = None
        if isinstance(meta, dict):
            external_app = meta.get("external_app_id")
        if not external_app:
            external_app = tool_doc.get("external_app_id")
        built_in = bool(tool_doc.get("built_in"))
        if not built_in and isinstance(meta, dict):
            built_in = bool(meta.get("built_in"))

        return external_app, built_in

    def _merge_dicts(self, base: Dict[str, Any], updates: Dict[str, Any]) -> None:
        for key, value in updates.items():
            if isinstance(value, dict) and isinstance(base.get(key), dict):
                self._merge_dicts(base[key], value)
            else:
                base[key] = value

    def _find_tool_by_key(self, tool_id: str) -> Any:
        """Fetch a tool by KV key from the in-memory manager cache."""
        if not tool_id or not self.tool_manager:
            return None

        return self.tool_manager.tools.get(tool_id)

    def _safe_json(self, response: Any) -> Any:
        try:
            return response.json()
        except (ValueError, AttributeError):
            return response.text

    def _is_kv_status(self, response: Any, allowed_statuses: Tuple[int, ...]) -> bool:
        """Check KV response status safely without assuming response shape."""
        return getattr(response, "status_code", None) in allowed_statuses

    def _extract_tool_names(self, tools: List[Dict[str, Any]]) -> List[str]:
        """Extract valid non-empty tool names from tool-like records."""
        tool_names: List[str] = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            tool_name = tool.get("name")
            if isinstance(tool_name, str) and tool_name:
                tool_names.append(tool_name)
        return tool_names

    def _current_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _create_kv_manager(self, session_key: str) -> KVStoreManager:
        return KVStoreManager(
            session_key=session_key,
            collection="mcp_tools",
            app_name=self.settings.app_name,
            owner="nobody",
        )

    def _create_enabled_kv_manager(self, session_key: str) -> KVStoreManager:
        return KVStoreManager(
            session_key=session_key,
            collection="mcp_tools_enabled",
            app_name=self.settings.app_name,
            owner="nobody",
        )

    def _cleanup_enabled_entries(
        self, tool_names: List[str], session_key: str
    ) -> List[str]:
        """Remove orphaned entries from the enabled tools collection.

        Best-effort: failures are logged as warnings but do not propagate.

        Returns:
            List of tool names whose enabled entries were successfully removed.
        """
        if not tool_names:
            return []

        enabled_kv_manager = self._create_enabled_kv_manager(session_key)
        cleaned: List[str] = []
        for tool_name in tool_names:
            try:
                del_resp = enabled_kv_manager.delete(tool_name)
                if self._is_kv_status(del_resp, (200, 204)):
                    cleaned.append(tool_name)
                elif not self._is_kv_status(del_resp, (404,)):
                    logger.warning(
                        "Failed to clean up enabled entry for '%s': %s",
                        tool_name,
                        getattr(del_resp, "text", ""),
                    )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "Error cleaning up enabled entry for '%s': %s",
                    tool_name,
                    exc,
                )
        if cleaned:
            logger.info(
                "Cleaned up %d orphaned enabled entries: %s",
                len(cleaned),
                cleaned,
            )
        return cleaned

    def _build_response(
        self, status: int, payload_obj: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "status": status,
            "headers": {"Content-Type": "application/json"},
            "payload": payload_obj,
        }

    def handleStream(self, handle: Any, in_string: str) -> None:  # pragma: no cover
        logger.warning("Streaming is not supported for MCP tools endpoint")
        return None

    def done(self) -> None:  # pragma: no cover
        logger.info("MCP Tools REST handler cleanup invoked")
