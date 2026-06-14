"""Contracts and response builders for MCP tools batch replace."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

Response = Tuple[int, Dict[str, Any]]


@dataclass(frozen=True)
class BatchReplaceRequest:
    """Validated request contract for batch replace payloads."""

    external_app_id: str
    tools: List[Any]

    @classmethod
    def from_payload(
        cls, payload: Dict[str, Any]
    ) -> Tuple[Optional["BatchReplaceRequest"], Optional[Response]]:
        """Parse and validate a raw payload dict into a BatchReplaceRequest.

        Returns:
            A (request, None) tuple on success, or (None, error_response) on failure.
        """
        external_app_id_raw = payload.get("external_app_id")
        external_app_id = (
            external_app_id_raw.strip() if isinstance(external_app_id_raw, str) else ""
        )
        if not external_app_id:
            return None, missing_external_app_id_response()

        tools = payload.get("tools")
        if not isinstance(tools, list):
            return None, invalid_tools_response()

        return cls(external_app_id=external_app_id, tools=tools), None


def missing_external_app_id_response() -> Response:
    return (
        400,
        {
            "error": True,
            "code": "missing_external_app_id",
            "message": "'external_app_id' is required for batch replace.",
        },
    )


def invalid_tools_response() -> Response:
    return (
        400,
        {
            "error": True,
            "code": "invalid_tools",
            "message": "'tools' must be a JSON array.",
        },
    )


def validation_error_response(errors: List[str]) -> Response:
    return (
        400,
        {
            "error": True,
            "code": "validation_error",
            "message": "Batch tool definition failed validation.",
            "details": errors,
        },
    )


def duplicate_tools_response(duplicate_tool_ids: List[str]) -> Response:
    return (
        400,
        {
            "error": True,
            "code": "duplicate_tools",
            "message": "Batch payload contains duplicate tools.",
            "details": sorted(set(duplicate_tool_ids)),
        },
    )


def kv_query_failed_response(status: int, details: Any) -> Response:
    return (
        status,
        {
            "error": True,
            "code": "kvstore_error",
            "message": "Failed to query existing tools for batch replace.",
            "details": details,
        },
    )


def kv_malformed_data_response() -> Response:
    return (
        502,
        {
            "error": True,
            "code": "kvstore_response_error",
            "message": "KV Store returned malformed data.",
        },
    )


def kv_unexpected_data_response() -> Response:
    return (
        502,
        {
            "error": True,
            "code": "kvstore_response_error",
            "message": "KV Store returned unexpected data format.",
        },
    )


def upsert_failure_response(
    external_app_id: str,
    registered_count: int,
    failed_inserts: List[Dict[str, Any]],
    rollback_failures: List[Dict[str, Any]],
) -> Response:
    """Build a 500 response for partial upsert failure with rollback details."""
    return (
        500,
        {
            "error": True,
            "code": "kvstore_error",
            "message": (
                "Failed to register one or more tools."
                if not rollback_failures
                else ("Failed to register one or more tools. Rollback was incomplete.")
            ),
            "external_app_id": external_app_id,
            "registered_count": registered_count,
            "failed_inserts": failed_inserts,
            "rollback_failures": rollback_failures,
        },
    )


def success_response(
    external_app_id: str,
    registered_count: int,
    deleted_count: int,
    skipped_built_in: List[Dict[str, str]],
    failed_deletes: List[Dict[str, Any]],
) -> Response:
    """Build a 200 response summarizing a completed batch replace operation."""
    message = "Replaced tools successfully."
    if failed_deletes:
        message = (
            "Tools registered successfully but some stale tools "
            "could not be removed."
        )

    response_payload: Dict[str, Any] = {
        "external_app_id": external_app_id,
        "message": message,
        "deleted_count": deleted_count,
        "registered_count": registered_count,
    }
    if skipped_built_in:
        response_payload["skipped_built_in"] = skipped_built_in
    if failed_deletes:
        response_payload["failed_deletes"] = failed_deletes

    return 200, response_payload
