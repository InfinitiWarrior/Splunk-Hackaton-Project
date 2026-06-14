import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List

from splunk.persistconn.application import PersistentServerConnectionApplication

_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

from http_utils import Request, Response
from logging_config import get_logger
from settings import MCPSettings
from tool_manager import get_default_manager

logger = get_logger(__name__)


@dataclass
class ToolCollisionsRequest:
    tool_ids: List[str] = field(default_factory=list)


@dataclass
class ToolCollisionsResponse:
    collisions: Dict[str, List[str]]


class MCPToolsCollisionsHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line: str, command_arg: str) -> None:
        super().__init__()
        self.tool_manager = get_default_manager(reload=False)

    def handle(self, in_string: str) -> Dict[str, Any]:
        try:
            raw = json.loads(in_string) if in_string else {}
            MCPSettings.set_splunkd_url_from_request(raw)
            request = Request(in_string)
        except ValueError as e:
            return Response.bad_request(str(e)).build()

        if request.method != "POST":
            return Response.method_not_allowed(request.method, ["POST"]).build()
        try:
            return self._handle_post(request)
        except Exception as e:
            logger.exception("Error handling request: %s", e)
            return Response.internal_server_error("Error processing request").build()

    def _handle_post(self, request: Request) -> Dict[str, Any]:
        """
        A handler accepts a list of tool_ids and returns collisions between those tools and already-enabled tools.
        Used for bulk-enable scenarios to detect potential tool conflicts before enabling multiple toolsl.
        """
        try:
            tool_ids = request.json()["tool_ids"]
            if not isinstance(tool_ids, list) or not all(
                isinstance(tool_id, str) for tool_id in tool_ids
            ):
                return Response.bad_request(
                    "tool_ids must be a list of strings"
                ).build()
        except (ValueError, TypeError, KeyError):
            return Response.bad_request("Invalid payload").build()

        self.tool_manager.refresh_custom_tools(request.session_key)
        collisions = self.tool_manager.find_collisions(tool_ids, request.session_key)
        return Response.ok().json({"collisions": collisions}).build()
