import os
import sys
from abc import ABC
from dataclasses import dataclass
from typing import List, Set

from logging_config import get_logger

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

import textdistance

logger = get_logger(__name__)


@dataclass
class ComparableTool:
    """
    Holds metadata used for collision detection.
    Args:
        name: The tool's name
        description: The tool's description
        tool_id: The tool ID. Required if available, as it is used in collision results.
    """

    name: str
    description: str
    tool_id: str = ""

    @property
    def comparison_text(self) -> str:
        return f"{self.name} {self.description}"

    def __hash__(self) -> int:
        return hash((self.tool_id, self.name))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ComparableTool):
            return NotImplemented
        return self.tool_id == other.tool_id and self.name == other.name


class ToolCollisionResult:
    """Outcome of a :meth:`ToolCollisionDetector#find_collisions` call."""

    def __init__(self, colliding_tools_ids: Set[str]) -> None:
        self.colliding_tools_ids = colliding_tools_ids

    def has_collisions(self) -> bool:
        return len(self.colliding_tools_ids) > 0


class ToolCollisionDetector(ABC):
    """Abstract class for detecting collisions in MCP Tools."""

    def find_collisions(
        self, tool: ComparableTool, tools_list: List[ComparableTool]
    ) -> ToolCollisionResult:
        """
        Find colliding tools by comparing a tool against a list of tools.

        Args:
            tool: The tool to check for collisions
            tools_list: List of tools to verify against. This SHOULD NOT include `tool` itself, a programmer should ensure that.
        """
        ...


@dataclass
class JaccardToolCollisionDetector(ToolCollisionDetector):
    """Jaccard similarity based implementation of ToolCollisionDetector.

    This algorithm does not filter the passed tool from the tools list. A programmer should ensure that.
    """

    threshold: float

    @staticmethod
    def _compute_jaccard_similarity(tool_desc_a: str, tool_desc_b: str) -> float:
        return textdistance.jaccard.normalized_similarity(tool_desc_a, tool_desc_b)

    def find_collisions(
        self, tool: ComparableTool, tools_list: List[ComparableTool]
    ) -> ToolCollisionResult:
        colliding_tool_ids: Set[str] = set()
        tool_metadata = tool.comparison_text
        for other_tool in tools_list:
            similarity = self._compute_jaccard_similarity(
                tool_metadata, other_tool.comparison_text
            )
            logger.debug(
                f"Jaccard similarity between '{tool.name}' and '{other_tool.tool_id}' is: {similarity}"
            )
            if similarity >= self.threshold:
                colliding_tool_ids.add(other_tool.tool_id)
        return ToolCollisionResult(colliding_tool_ids)
