from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from kvstore_manager import KVStoreManager


@dataclass
class EnabledTool:
    """Domain class representing an enabled MCP Tool."""

    name: str
    tool_id: str
    collision_ids: Set[str] = field(default_factory=set)

    def add_collision(self, other_collision_id: str) -> None:
        self.collision_ids.add(other_collision_id)

    def discard_collision(self, other_collision_id: str) -> None:
        self.collision_ids.discard(other_collision_id)

    def add_collisions(self, other_collisions_ids: Iterable) -> None:
        self.collision_ids.update(other_collisions_ids)

    def to_db_model(self) -> Dict[str, Any]:
        return {
            "_key": self.name,
            "tool_id": self.tool_id,
            "collision_ids": list(self.collision_ids),
        }

    @staticmethod
    def from_db_model(data: Dict[str, Any]) -> "EnabledTool":
        tool_name = data.get("_key", "")
        tool_id = data.get("tool_id", "")
        collision_ids = set(data.get("collision_ids", []))
        return EnabledTool(tool_name, tool_id, collision_ids)

    def to_api_model(self) -> Dict[str, Any]:
        return {
            "tool_name": self.name,
            "tool_id": self.tool_id,
            "collision_ids": list(self.collision_ids),
        }


# Key used in the enabled-tools KV store to mark that built-in tools have been seeded.
# Excluded from "all enabled tools" queries so it is not treated as a tool.
_ENABLED_SEED_MARKER_KEY = "__mcp_tools_seeded__"


class ToolCollectionError(Exception):
    """Base exception for tool collection operations."""

    pass


class ToolEnabledCollection:
    """Class for performing operations on the enabled tools KV Store collection."""

    def __init__(self, session_key: str) -> None:
        self._kv_manager = KVStoreManager(
            session_key=session_key,
            collection="mcp_tools_enabled",
        )

    def get_all_except(self, except_key: str) -> List[EnabledTool]:
        response = self._kv_manager.query(
            query={"_key": {"$ne": except_key}}, output_mode="json", count="0"
        )
        if response.status_code == 200:
            tools_data = response.json()
            return [EnabledTool.from_db_model(tool_data) for tool_data in tools_data]
        else:
            raise ToolCollectionError(
                f"Failed to retrieve enabled tool data. {response.text}"
            )

    def get_all_enabled_tools(self) -> List[EnabledTool]:
        """Return all enabled tools, excluding the built-in seed marker record."""
        return self.get_all_except(_ENABLED_SEED_MARKER_KEY)

    def has_seed_marker(self) -> bool:
        """Return True if the built-in tools seeded marker exists in the collection."""
        response = self._kv_manager.get(_ENABLED_SEED_MARKER_KEY)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            raise ToolCollectionError(
                f"Failed to retrieve seed marker. {response.text}"
            )

    def get(self, tool_name: str) -> Optional[EnabledTool]:
        response = self._kv_manager.get(tool_name)
        if response.status_code == 200:
            tool_data = response.json()
            return EnabledTool.from_db_model(tool_data)
        elif response.status_code == 404:
            return None
        else:
            raise ToolCollectionError(
                f"Failed to retrieve enabled tool data. {response.text}"
            )

    def get_by_tool_id(self, tool_id: str) -> Optional[EnabledTool]:
        response = self._kv_manager.query({"tool_id": tool_id}, output_mode="json")
        if response.status_code == 200:
            tools_data = response.json()
            if len(tools_data) == 0:
                return None
            return EnabledTool.from_db_model(tools_data[0])
        else:
            raise ToolCollectionError(
                f"Failed to retrieve enabled tool data. {response.text}"
            )

    def get_by_tool_ids(self, tool_ids: List[str]) -> List[EnabledTool]:
        response = self._kv_manager.query(
            {"tool_id": {"$in": tool_ids}}, output_mode="json", count="0"
        )
        if response.status_code == 200:
            tools_data = response.json()
            return [EnabledTool.from_db_model(tool_data) for tool_data in tools_data]
        else:
            raise ToolCollectionError(
                f"Failed to retrieve enabled tools by IDs. {response.text}"
            )

    def upsert(self, enabled_tool: EnabledTool) -> None:
        enabled_tool_to_insert = enabled_tool.to_db_model()
        replace_response = self._kv_manager.replace(
            enabled_tool.name, enabled_tool_to_insert
        )
        if replace_response.status_code == 404:
            insert_response = self._kv_manager.insert(enabled_tool_to_insert)
            if insert_response.status_code not in (200, 201):
                raise ToolCollectionError(
                    f"Failed to insert enabled tool data. {insert_response.text}"
                )
        elif replace_response.status_code not in (200, 201):
            raise ToolCollectionError(
                f"Failed to upsert enabled tool data. {replace_response.text}"
            )

    def replace(self, enabled_tool: EnabledTool) -> None:
        enabled_tool_to_replace = enabled_tool.to_db_model()
        response = self._kv_manager.replace(enabled_tool.name, enabled_tool_to_replace)
        if response.status_code not in (200, 201):
            raise ToolCollectionError(
                f"Failed to update enabled tool data. {response.text}"
            )

    def delete(self, tool_name: str) -> None:
        response = self._kv_manager.delete(tool_name)
        if response.status_code not in (200, 404):
            raise ToolCollectionError(
                f"Failed to delete enabled tool data. {response.text}"
            )

    def batch_save(
        self, enabled_tools: List[EnabledTool], push_seed_marker: bool = False
    ) -> None:
        documents = [tool.to_db_model() for tool in enabled_tools]
        if push_seed_marker:
            documents.append({"_key": _ENABLED_SEED_MARKER_KEY, "seeded": True})
        response = self._kv_manager.batch_save(documents)
        if response is None:
            return
        if response.status_code not in (200, 201):
            raise ToolCollectionError(
                f"Failed to batch save enabled tools. {response.text}"
            )
