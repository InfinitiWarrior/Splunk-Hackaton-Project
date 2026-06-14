import json
import os
import sys
import traceback
from typing import Any, Callable, Dict

from splunk.persistconn.application import PersistentServerConnectionApplication

_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)


from http_utils import Request, Response
from logging_config import clear_log_context, get_logger, update_log_context_req_id
from rate_limit_manager import RateLimitDTO, RateLimitManager, RateLimits
from settings import MCPSettings
from tool_manager import get_default_manager

logger = get_logger(__name__)


class MCPRateLimitsHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line: str, command_arg: str) -> None:
        super().__init__()
        self._handlers: Dict[
            str, Callable[[Request, RateLimitManager], Dict[str, Any]]
        ] = {
            "POST": self._handle_post,
            "GET": self._handle_get,
        }
        self._tool_manager = get_default_manager(reload=False)

    def handle(self, in_string: str) -> Dict[str, Any]:
        update_log_context_req_id()
        try:
            try:
                raw = json.loads(in_string) if in_string else {}
                MCPSettings.set_splunkd_url_from_request(raw)
                request = Request(in_string)
            except ValueError as e:
                return Response.bad_request(str(e)).build()

            if request.session_key is None:
                return Response.unauthorized().build()

            handler = self._handlers.get(request.method)
            if handler is None:
                return Response.method_not_allowed(
                    request.method, list(self._handlers.keys())
                ).build()

            rate_limit_manager = RateLimitManager(request.session_key)
            return handler(request, rate_limit_manager)
        except Exception as e:
            error_message = traceback.format_exc()
            logger.exception(
                f"Unexpected error occurred while handling request: {e}, stack trace: {error_message}"
            )
            return Response.internal_server_error(
                "An unexpected error occurred while processing the request."
            ).build()
        finally:
            clear_log_context()

    def _handle_get(
        self, request: Request, rate_limit_manager: RateLimitManager
    ) -> Dict[str, Any]:
        rate_limits = rate_limit_manager.get_rate_limits()

        dto = RateLimitDTO.from_settings(rate_limits).as_api_response()
        return Response.ok().json(dto).build()

    def _handle_post(
        self, request: Request, rate_limit_manager: RateLimitManager
    ) -> Dict[str, Any]:
        try:
            update_request = RateLimitDTO.from_json_string(request.raw_payload)
        except Exception as e:
            logger.exception(f"Invalid payload, error: {e}")
            return Response.bad_request("Invalid JSON payload").build()

        errors = update_request.validate()
        if errors:
            return Response.bad_request(errors).build()

        self._tool_manager.refresh_custom_tools(request.session_key)
        rate_limits_from_request = RateLimits(data=update_request.limits)
        new_rate_limits = rate_limits_from_request.prune_nonexistent_tools(
            self._tool_manager.tools.keys()
        )
        if rate_limit_manager.update_rate_limits(new_rate_limits):
            logger.info(f"Rate limits updated successfully: {new_rate_limits}")
            return Response.ok().build()

        return Response.internal_server_error(
            "Failed to update rate limits. Please check the logs for more details."
        ).build()
